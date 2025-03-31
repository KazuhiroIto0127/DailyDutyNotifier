import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, ScanCommand, GetCommand, UpdateCommand } from '@aws-sdk/lib-dynamodb';
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

// ★ 新しい日直を選出するロジック (現在の担当者と前回担当者を除外)
const selectNewDutyMember = (members, currentMemberId, lastAssignedId) => {
  if (!members || members.length === 0) {
    logger.error("Member list is empty.");
    return null;
  }
  // 除外するIDのセットを作成
  const excludeIds = new Set([currentMemberId, lastAssignedId]);
  logger.info(`Excluding IDs: ${Array.from(excludeIds).join(', ')}`);

  let candidates = members.filter(m => !excludeIds.has(m.memberId));

  if (candidates.length === 0) {
    logger.warn("No candidates after excluding current and last assigned. Trying excluding only current.");
    candidates = members.filter(m => m.memberId !== currentMemberId);
    if (candidates.length === 0) {
      logger.warn("No candidates even after excluding only current. Selecting from all members (could result in the same member).");
      candidates = [...members]; // 最悪全員から選ぶ（同じ人が再度選ばれる可能性も）
    }
  }
  if (candidates.length === 0) { // 全員除外されてしまった場合（ありえないはずだが）
    logger.error("Cannot select new member, no candidates available at all.");
    return null;
  }


  // dutyCount昇順 -> memberId昇順でソート (notifyDutyHandlerと同様)
  candidates.sort((a, b) => {
    if (a.dutyCount !== b.dutyCount) {
      return a.dutyCount - b.dutyCount;
    }
    return (a.memberId || '').localeCompare(b.memberId || '');
  });

  const newMember = candidates[0];
  logger.info(`New member selected: ${newMember.memberId} (Count: ${newMember.dutyCount})`);
  return newMember;
};

// ★ 再選出時のDynamoDB更新ロジック
const updateDynamoDBForReselection = async (originalMemberId, newMember) => {
  const newMemberId = newMember.memberId;
  try {
    // 1. 元の担当者のカウントをデクリメント (-1)
    //    注意: カウントが0未満にならないような制御はここでは省略（必要ならConditionExpression追加）
    const decrementCommand = new UpdateCommand({
      TableName: membersTableName,
      Key: { memberId: originalMemberId },
      UpdateExpression: "ADD dutyCount :dec",
      ExpressionAttributeValues: { ':dec': -1 },
      ReturnValues: "UPDATED_NEW",
    });
    const decResult = await docClient.send(decrementCommand);
    logger.info(`Decremented duty count for original member ${originalMemberId}. New count: ${decResult.Attributes?.dutyCount}`);

    // 2. 新しい担当者のカウントをインクリメント (+1)
    const incrementCommand = new UpdateCommand({
      TableName: membersTableName,
      Key: { memberId: newMemberId },
      UpdateExpression: "ADD dutyCount :inc",
      ExpressionAttributeValues: { ':inc': 1 },
      ReturnValues: "UPDATED_NEW",
    });
    const incResult = await docClient.send(incrementCommand);
    logger.info(`Incremented duty count for new member ${newMemberId}. New count: ${incResult.Attributes?.dutyCount}`);

    // 3. DutyState の lastAssignedMemberId を新しい担当者で更新
    //    lastAssignmentDate は元の通知日のままにする想定
    const updateStateCommand = new UpdateCommand({
      TableName: stateTableName,
      Key: { stateId: stateId },
      UpdateExpression: "SET lastAssignedMemberId = :new_id",
      ExpressionAttributeValues: { ':new_id': newMemberId },
      // ConditionExpression: "lastAssignedMemberId = :original_id", // 必要なら現在の値を確認
      // ExpressionAttributeValues: { ':new_id': newMemberId, ':original_id': originalMemberId },
    });
    await docClient.send(updateStateCommand);
    logger.info(`Updated duty state lastAssignedMemberId to ${newMemberId}`);

  } catch (error) {
    logger.error(`Error updating DynamoDB during reselection: ${error}`);
    // ConditionalCheckFailedException などもここで捕捉される
    throw error;
  }
};

// --- ヘルパー関数: メンバーリスト表示用ブロック作成 ---
const createMemberListBlocks = (members) => {
  if (!members || members.length === 0) {
    return []; // メンバーデータがない場合は空配列
  }

  // 見やすいように名前順でソート (任意)
  members.sort((a, b) => (a.memberName || a.memberId || '').localeCompare(b.memberName || b.memberId || ''));

  let memberListText = "*現在の担当回数:*\n";
  members.forEach(member => {
    // Slackでメンション形式(<@Uxxxx>)にしたい場合は memberId を使う
    // const name = member.memberId.startsWith('U') || member.memberId.startsWith('W') ? `<@${member.memberId}>` : (member.memberName || member.memberId);
    const name = member.memberName || member.memberId; // 通常は名前を表示
    const count = member.dutyCount || 0;
    memberListText += `• ${name}: ${count}回\n`;
  });

  // context ブロックを使うと少しコンパクトに表示される
  return [
    { type: 'divider' }, // 区切り線
    {
      type: 'context',
      elements: [
        {
          type: 'mrkdwn',
          text: memberListText
        }
      ]
    }
    // または Section ブロックで表示する場合:
    // {
    //     type: 'section',
    //     text: {
    //         type: 'mrkdwn',
    //         text: memberListText
    //     }
    // }
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
    const currentMemberId = buttonValue.current_member_id; // ボタンのvalueに埋め込んだ元の担当者ID
    const channelId = payload.container?.channel_id;
    const messageTs = payload.container?.message_ts; // 元のメッセージのタイムスタンプ
    const userId = payload.user?.id; // ボタンを押したユーザーのID

    if (!currentMemberId || !channelId || !messageTs) {
      logger.error("Missing required info (current_member_id, channel_id, message_ts) in payload.");
      // エラーをユーザーに伝えるのは難しいのでログに残す
      return { statusCode: 200, body: 'OK (Missing info in payload)' }; // SlackにはACKを返す
    }
    logger.info(`Reselection requested for current member ${currentMemberId} in channel ${channelId}, message ${messageTs} by user ${userId}`);

    // --- ここからが実際の再選出処理 ---
    // Slackは3秒以内にACK応答を期待するため、重い処理は非同期化推奨だが、
    // 今回は同期的に処理してみる

    // --- 4. DynamoDBからデータを取得 ---
    const [dutyState, allMembers] = await Promise.all([
      getDutyState(),
      getAllMembers()
    ]);

    if (allMembers.length === 0) {
      logger.error("No members found in DynamoDB.");
      // 元のメッセージを更新してエラーを伝える
      await slackClient.chat.update({ channel: channelId, ts: messageTs, text: "エラー: メンバー情報が見つかりません。", blocks: [] });
      return { statusCode: 200, body: 'OK (Member fetch error)' };
    }

    // --- 5. 新しい日直を選出 ---
    const lastAssignedId = dutyState.lastAssignedMemberId;  // ★ 前回の最終担当者
    // ★★★ selectNewDutyMember に渡す lastAssignedId は、DutyStateから取得した、
    // ★★★ その日の最初の担当者（または前回ボタンで変更された担当者）のはず。
    // ★★★ ボタンのValueには「現在表示されている担当者」が入る。
    // ★★★ 混乱を避けるため、DutyState の lastAssignedMemberId を「前日の最終担当者」ではなく、
    // ★★★ 「その日の現在(最新)の担当者」として扱うように updateDynamoDBForReselection を修正する。
    // ★★★ -> いや、やはり現状のままでOK。「前回担当者」は DutyState.lastAssignedMemberId で、
    // ★★★ 「現在の表示担当者」は buttonValue.current_member_id で区別できる。
    const newMember = selectNewDutyMember(allMembers, currentMemberId, lastAssignedId);

    if (!newMember) {
      logger.error("Failed to select a new member (no candidates?).");
      await slackClient.chat.update({ channel: channelId, ts: messageTs, text: "エラー: 代わりの担当者を選出できませんでした。", blocks: [] });
      return { statusCode: 200, body: 'OK (Reselection failed)' };
    }

    // --- 6. DynamoDBのデータを更新 ---
    await updateDynamoDBForReselection(currentMemberId, newMember);

    // ★★★ Slack更新前に最新のメンバー情報を再取得 ★★★
    const updatedMembers = await getAllMembers();

    // --- 7. 元のSlackメッセージを更新 ---
    await updateSlackMessage(channelId, messageTs, newMember, currentMemberId, userId, updatedMembers);


    // --- 8. 正常終了のACK応答 ---
    logger.info("Reselection process completed successfully.");
    return { statusCode: 200, body: 'OK (Reselection processed)' };

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
