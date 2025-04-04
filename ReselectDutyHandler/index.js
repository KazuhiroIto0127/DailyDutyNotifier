import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, ScanCommand, GetCommand, UpdateCommand, PutCommand } from '@aws-sdk/lib-dynamodb';
import { WebClient } from '@slack/web-api';
import { createHmac } from 'crypto';
import querystring from 'querystring'; // ★ ペイロード解析用
import crypto from 'crypto';

// --- 設定 ---
const logger = console;
const region = process.env.AWS_REGION || 'ap-northeast-1';
const membersTableName = process.env.MEMBERS_TABLE_NAME;
const stateTableName = process.env.STATE_TABLE_NAME;
const stateId = process.env.STATE_ID;
const slackToken = process.env.SLACK_BOT_TOKEN;
const slackSigningSecret = process.env.SLACK_SIGNING_SECRET; // ★ Slack署名シークレット

// 環境変数チェック
if (!membersTableName || !stateTableName || !stateId || !slackToken || !slackSigningSecret) {
  logger.error('Error: Required environment variables are missing!');
  throw new Error('Missing required environment variables.');
}

// AWS SDK, Slack クライアント初期化 (notifyDutyHandlerと同様)
const dynamoClient = new DynamoDBClient({ region });
const docClient = DynamoDBDocumentClient.from(dynamoClient);
const slackClient = new WebClient(slackToken);

// DutyStateテーブルから現在の状態を取得
const getDutyState = async () => {
  const command = new GetCommand({
    TableName: stateTableName,
    Key: { stateId: stateId },
  });
  try {
    const { Item } = await docClient.send(command);
    logger.info(`Duty state retrieved: ${JSON.stringify(Item)}`);
    return Item || { lastAssignedMemberId: null, lastAssignmentDate: null }; // データなければデフォルト
  } catch (error) {
    logger.error(`Error getting duty state from ${stateTableName}: ${error}`);
    throw error;
  }
};

// DutyMembersテーブルから全メンバーを取得
const getAllMembers = async () => {
  const command = new ScanCommand({ TableName: membersTableName });
  try {
    const { Items } = await docClient.send(command);
    logger.info(`Scanned ${Items?.length || 0} members from ${membersTableName}`);
    // dutyCount が数値でない場合や存在しない場合に備えてデフォルト値0を設定
    return Items?.map(item => ({ ...item, dutyCount: Number(item.dutyCount) || 0 })) || [];
  } catch (error) {
    logger.error(`Error scanning members from ${membersTableName}: ${error}`);
    throw error;
  }
};

const verifySlackRequest = (event) => {
  const signature = event.headers['x-slack-signature'] || event.headers['X-Slack-Signature'];
  const timestamp = event.headers['x-slack-request-timestamp'] || event.headers['X-Slack-Request-Timestamp'];
  const body = event.body; // Lambda Proxy統合からの生のボディ文字列を想定
  const signingSecret = process.env.SLACK_SIGNING_SECRET; // 環境変数から取得

  if (!signature || !timestamp || !body || !signingSecret) {
    logger.warn("Missing Slack signature headers, body, or signing secret.");
    return false;
  }

  // timestampが古すぎるかチェック (5分以上前は拒否)
  const fiveMinutesAgo = Math.floor(Date.now() / 1000) - (60 * 5);
  if (parseInt(timestamp, 10) < fiveMinutesAgo) {
    logger.warn(`Timestamp too old: ${timestamp}. Rejecting.`);
    return false;
  }

  // --- ここから署名検証ロジック ---
  // @slack/events-api の createEventAdapter の verifyRequest 相当の処理を自前実装
  try {
    const baseString = `v0:${timestamp}:${body}`;
    const hmac = createHmac('sha256', signingSecret);
    const computedSignature = `v0=${hmac.update(baseString).digest('hex')}`;

    // crypto.timingSafeEqual を使って比較 (タイミング攻撃対策)
    const receivedSigBuffer = Buffer.from(signature, 'utf8');
    const computedSigBuffer = Buffer.from(computedSignature, 'utf8');

    if (receivedSigBuffer.length !== computedSigBuffer.length) {
      logger.warn(`Signature length mismatch. Received: ${receivedSigBuffer.length}, Computed: ${computedSigBuffer.length}`);
      return false;
    }

    const signaturesMatch = crypto.timingSafeEqual(receivedSigBuffer, computedSigBuffer);

    if (signaturesMatch) {
      logger.info("Slack signature verified successfully.");
      return true;
    } else {
      logger.warn("Signature mismatch.");
      // logger.debug(`Received: ${signature}, Computed: ${computedSignature}`); // デバッグ用
      return false;
    }
  } catch (error) {
    logger.error(`Error during signature verification: ${error.message}`);
    return false;
  }
};

// ★ DB更新ロジック (カウント増減 + DutyState の Index と MemberId 更新)
const updateDutyDataOnReselect = async (originalMemberId, newMemberId, newIndex, currentState) => {
  // currentState から assignmentDate と rotationList を引き継ぐ
  const assignmentDate = currentState.assignmentDate;
  const rotationList = currentState.rotationList;

  if (!assignmentDate || !rotationList || rotationList.length === 0) {
    logger.error("Cannot update state on reselect: Missing assignmentDate or rotationList in current state.");
    // ここでエラーにするか、部分的に更新するか選択。エラーにするのが安全か。
    throw new Error("Invalid duty state for reselection.");
  }

  try {
    // 1. 元の担当者のカウントを-1
    const decrementCommand = new UpdateCommand({
      TableName: membersTableName, Key: { memberId: originalMemberId },
      UpdateExpression: "ADD dutyCount :dec", ExpressionAttributeValues: { ':dec': -1 },
      ReturnValues: "UPDATED_NEW",
    });
    const decResult = await docClient.send(decrementCommand);
    logger.info(`Decremented count for ${originalMemberId}. New: ${decResult.Attributes?.dutyCount}`);

    // 2. 新しい担当者のカウントを+1
    const incrementCommand = new UpdateCommand({
      TableName: membersTableName, Key: { memberId: newMemberId },
      UpdateExpression: "ADD dutyCount :inc", ExpressionAttributeValues: { ':inc': 1 },
      ReturnValues: "UPDATED_NEW",
    });
    const incResult = await docClient.send(incrementCommand);
    logger.info(`Incremented count for ${newMemberId}. New: ${incResult.Attributes?.dutyCount}`);

    // 3. DutyState テーブルを更新 (PutCommandで必須項目含めて上書き)
    const putStateCommand = new PutCommand({
      TableName: stateTableName,
      Item: {
        stateId: stateId,
        assignmentDate: assignmentDate, // 日付は維持
        rotationList: rotationList,     // リストも維持
        currentListIndex: newIndex,     // ★ 新しいインデックス
        currentAssignedMemberId: newMemberId, // ★ 新しい担当者ID
      },
    });
    await docClient.send(putStateCommand);
    logger.info(`Updated duty state: New index ${newIndex}, New member ${newMemberId}`);

  } catch (error) {
    logger.error(`Error updating data on reselect (original: ${originalMemberId}, new: ${newMemberId}): ${error}`);
    throw error;
  }
};

// ★ メンバーリスト表示用ブロック作成 (displayOrder でソート)
const createMemberListBlocks = (members) => {
  if (!members || members.length === 0) return [];

  // ★★★ displayOrder でソート ★★★
  members.sort((a, b) => {
    const orderA = a.displayOrder ?? Infinity;
    const orderB = b.displayOrder ?? Infinity;
    if (orderA !== orderB) {
      return orderA - orderB;
    }
    return (a.memberId || '').localeCompare(b.memberId || ''); // displayOrder が同じ場合の予備ソート
  });

  let memberListText = "*現在の担当回数 (表示順):*\n"; // タイトル変更
  members.forEach(member => {
    const name = member.memberName || member.memberId;
    const count = member.dutyCount || 0;
    memberListText += `• ${name}: ${count}回\n`;
  });

  return [
    { type: 'divider' },
    {
      type: 'context',
      elements: [{ type: 'mrkdwn', text: memberListText }]
    }
  ];
};

// ★ 元のSlackメッセージを更新する関数
const updateSlackMessage = async (channelId, messageTs, newMember, originalMemberId, reselectorUserId, members) => { // ★ originalMemberId も受け取る
  const newMemberId = newMember.memberId;
  const newMemberMention = newMemberId.startsWith('U') || newMemberId.startsWith('W') ? `<@${newMemberId}>` : (newMember.memberName || newMemberId);
  const originalMemberMention = originalMemberId.startsWith('U') || originalMemberId.startsWith('W') ? `<@${originalMemberId}>` : originalMemberId; // 元の担当者も表示（任意）
  const reselectorMention = reselectorUserId ? `<@${reselectorUserId}>` : "誰か";

  // メッセージ本文を更新
  const text = `🔄 ${reselectorMention} さんが担当者を変更しました。\n新しい担当は ${newMemberMention} さんです！ (元の担当: ${originalMemberMention})`;
  // ★ メンバーリスト表示用のブロックを作成
  const memberListBlocks = createMemberListBlocks(members);

  try {
    await slackClient.chat.update({
      channel: channelId,
      ts: messageTs,
      text: text, // フォールバックテキストも更新
      blocks: [
        {
          "type": "section",
          "text": {
            "type": "mrkdwn",
            "text": text // 更新されたメッセージ本文
          }
        },
        // { // コンテキスト情報として元の担当者などを表示しても良い (任意)
        //     "type": "context",
        //     "elements": [
        //         { "type": "mrkdwn", "text": `元の担当: ${originalMemberMention}` }
        //     ]
        // },
        { // ★ ボタンを含む actions ブロックを再度追加 (ボタンは消さない)
          "type": "actions",
          "block_id": "duty_actions", // 同じ block_id
          "elements": [
            {
              "type": "button",
              "text": {
                "type": "plain_text",
                "text": "担当を変更する", // ボタンのテキストは同じ
                "emoji": true
              },
              "style": "danger",
              "action_id": "reselect_duty_action", // 同じ action_id
              // ★★★ 重要: value には *新しい* 担当者のIDを入れる ★★★
              "value": JSON.stringify({ current_member_id: newMemberId })
            }
          ]
        },
        // ★★★ 作成したメンバーリストブロックを追加 ★★★
        ...memberListBlocks
      ]
    });
    logger.info(`Updated Slack message ${messageTs} with new duty member ${newMemberId}, keeping the button.`);
  } catch (error) {
    logger.error(`Error updating Slack message ${messageTs}: ${error.data?.error || error.message}`);
    // エラー処理はそのまま
  }
};


// --- Lambdaハンドラー ---
export const handler = async (event, context) => {
  // ★ API Gateway v2/HTTP APIペイロードを想定。v1/REST API Proxyの場合は少し異なる可能性あり。
  //    Lambdaコンソールでのテスト時には、実際のAPI Gatewayからのevent形式を模倣する必要あり。
  // logger.info(`Raw event: ${JSON.stringify(event)}`); // デバッグ用に生イベントを出力

  // --- 1. Slackリクエスト署名検証 ---
  if (!verifySlackRequest(event)) {
    logger.error("Invalid Slack signature.");
    // Slackには通常エラーでも200 OKを返すことが推奨される場合があるが、
    // 不正リクエストは明確に拒否するため403を返す
    return { statusCode: 403, body: 'Invalid signature' };
  }

  // --- 2. ペイロード解析 ---
  let payload;
  try {
    // Slackインタラクションのペイロードは x-www-form-urlencoded 形式の body に 'payload' キーで格納されている
    const parsedBody = querystring.parse(event.body);
    const payloadStr = parsedBody.payload;
    if (!payloadStr || typeof payloadStr !== 'string') {
      throw new Error("Payload string not found or not a string in body");
    }
    payload = JSON.parse(payloadStr);
    logger.info(`Interaction payload received: type=${payload.type}, action_id=${payload.actions?.[0]?.action_id}`);
    // logger.debug(`Full payload: ${JSON.stringify(payload)}`); // 詳細デバッグ用

    // Block Kitのボタンアクションか確認
    if (payload.type !== 'block_actions' || !payload.actions || payload.actions.length === 0) {
      logger.info("Not a block_actions payload or no actions found. Acknowledging.");
      return { statusCode: 200, body: 'OK (Not a target action)' }; // SlackへのACK応答
    }

    const action = payload.actions[0];
    // notifyDutyHandlerで設定したaction_idか確認
    if (action.action_id !== 'reselect_duty_action') {
      logger.info(`Ignoring action_id: ${action.action_id}. Acknowledging.`);
      return { statusCode: 200, body: 'OK (Ignoring action)' };
    }

    // --- 3. 必要な情報をペイロードから抽出 ---
    const buttonValue = JSON.parse(action.value || '{}');
    const currentMemberIdFromButton = buttonValue.current_member_id; // ボタンに紐づいた担当者
    const channelId = payload.container?.channel_id;
    const messageTs = payload.container?.message_ts; // 元のメッセージのタイムスタンプ
    const userId = payload.user?.id; // ボタンを押したユーザーのID

    if (!currentMemberIdFromButton || !channelId || !messageTs) {
      logger.error("Missing required info (current_member_id, channel_id, message_ts) in payload.");
      // エラーをユーザーに伝えるのは難しいのでログに残す
      return { statusCode: 200, body: 'OK (Missing info in payload)' }; // SlackにはACKを返す
    }
    logger.info(`Reselection requested for current member ${currentMemberIdFromButton} in channel ${channelId}, message ${messageTs} by user ${userId}`);

    // --- ここからが実際の再選出処理 ---
    // Slackは3秒以内にACK応答を期待するため、重い処理は非同期化推奨だが、
    // 今回は同期的に処理してみる

    // --- 再選出処理 ---
    // ★★★ DutyState からローテーションリストと現在のインデックスを取得 ★★★
    const currentState = await getDutyState();
    const rotationList = currentState.rotationList;
    const currentListIndex = currentState.currentListIndex;
    // 念のため、ボタンのIDとStateのIDが一致するか確認 (通常は一致するはず)
    if (currentState.currentAssignedMemberId !== currentMemberIdFromButton) {
      logger.warn(`Button member ID (${currentMemberIdFromButton}) does not match current state member ID (${currentState.currentAssignedMemberId}). Proceeding based on button value.`);
      // ボタンの値を正として進めるか、エラーにするか選択。ここではボタンの値で進める。
    }


    if (!rotationList || rotationList.length === 0 || currentListIndex === undefined || currentListIndex < 0) {
      logger.error("Invalid rotation data in DutyState. Cannot proceed with reselection.");
      await slackClient.chat.postEphemeral({ channel: channelId, user: userId, text: "エラー: ローテーション情報が見つからないため、担当者を変更できません。" });
      return { statusCode: 200, body: 'OK (Invalid rotation state)' };
    }
    if (rotationList.length <= 1) {
      logger.warn("Only one member in rotation list. Cannot reselect.");
      await slackClient.chat.postEphemeral({ channel: channelId, user: userId, text: "交代できる他の担当がいません。" });
      return { statusCode: 200, body: 'OK (Only one member)' };
    }


    // ★ 次の担当者のインデックスとIDを決定
    const nextIndex = (currentListIndex + 1) % rotationList.length;
    const newMemberId = rotationList[nextIndex];
    logger.info(`Next member determined from rotation list: Index ${nextIndex}, ID ${newMemberId}`);

    // ★ DynamoDB更新 (カウント増減 + StateのIndex/MemberId更新)
    await updateDutyDataOnReselect(currentMemberIdFromButton, newMemberId, nextIndex, currentState);

    // ★ Slackメッセージ更新用の情報を取得
    //   最新のメンバー情報(カウント反映後)と、新しい担当者の詳細情報が必要
    const [updatedMembers, newMemberDetailsList] = await Promise.all([
      getAllMembers(), // 最新の全メンバーリスト(表示用)
      docClient.send(new GetCommand({ TableName: membersTableName, Key: { memberId: newMemberId } })) // 新担当者の詳細取得
    ]);
    const newMember = newMemberDetailsList.Item; // 新担当者のオブジェクト

    if (!newMember) {
      logger.error(`Failed to get details for the newly selected member ${newMemberId}`);
      // エラー処理...（メッセージ更新は試みる）
      await updateSlackMessage(channelId, messageTs, { memberId: newMemberId }, currentMemberIdFromButton, userId, updatedMembers); // IDだけでも渡す
      return { statusCode: 200, body: 'OK (Failed to get new member details)' };
    }


    // ★ Slackメッセージ更新
    await updateSlackMessage(channelId, messageTs, newMember, currentMemberIdFromButton, userId, updatedMembers);

    logger.info("List rotation reselection process completed successfully.");
    return { statusCode: 200, body: 'OK (List rotation reselection processed)' };

  } catch (error) {
    logger.error(`Error handling Slack interaction: ${error.message}`);
    logger.error(error.stack); // スタックトレースも出力

    // エラーが発生した場合でもSlackにはACK(200 OK)を返すのが一般的
    // 可能であれば元のメッセージを更新してエラーを伝える試み
    try {
      if (payload?.container?.channel_id && payload?.container?.message_ts) {
        await slackClient.chat.update({
          channel: payload.container.channel_id,
          ts: payload.container.message_ts,
          text: `エラーが発生しました: ${error.message || '不明なエラー'}`,
          blocks: []
        });
      }
    } catch (slackError) {
      logger.error(`Failed to send error update to Slack: ${slackError}`);
    }

    return { statusCode: 200, body: 'OK (Internal server error occurred)' };
  }
};
