import { WebClient } from '@slack/web-api';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, ScanCommand, GetCommand, PutCommand, UpdateCommand } from '@aws-sdk/lib-dynamodb';
import holiday_jp from '@holiday-jp/holiday_jp';
import { formatInTimeZone } from 'date-fns-tz';

// --- 設定 ---
const logger = console;
const region = process.env.AWS_REGION || 'ap-northeast-1';
const slackToken = process.env.SLACK_BOT_TOKEN;
const slackChannelId = process.env.SLACK_CHANNEL_ID;
const membersTableName = process.env.MEMBERS_TABLE_NAME;
const stateTableName = process.env.STATE_TABLE_NAME;
const stateId = process.env.STATE_ID;
const timeZone = process.env.TZ || 'Asia/Tokyo';

// 環境変数チェック
if (!slackToken || !slackChannelId || !membersTableName || !stateTableName || !stateId || !timeZone) { // ★ state関連とTZもチェック
  logger.error('Error: Required environment variables are missing.');
  throw new Error('Missing required environment variables.');
}

// AWS SDK クライアント
const dynamoClient = new DynamoDBClient({ region });
const docClient = DynamoDBDocumentClient.from(dynamoClient);
const slackClient = new WebClient(slackToken);

// --- ヘルパー関数 ---
const isWeekdayInZone = (date, tz) => {
  // 1. 指定タイムゾーンでの曜日を取得 (0=日曜, 6=土曜)
  // formatInTimeZone を使って曜日番号('i')を取得し数値に変換
  const dayOfWeek = parseInt(formatInTimeZone(date, tz, 'i'), 10);
  if (dayOfWeek === 0 || dayOfWeek === 6) {
    logger.info(`Detected weekend (Day: ${dayOfWeek}) in ${tz}`);
    return false;
  }

  // 2. 日本の祝日かどうかチェック (@holiday-jp/holiday_jp は Date オブジェクトを渡せばOK)
  // 注意: holiday_jp は内部で日本の日付として解釈するため、渡すDateオブジェクトのUTC時刻は意識しなくて良いはず
  if (holiday_jp.isHoliday(date)) {
    logger.info(`Detected holiday in Japan: ${formatInTimeZone(date, tz, 'yyyy-MM-dd')}`);
    return false;
  }
  return true;
};

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

// ★ 最初の担当者を選出するロジック (変更なし)
const selectFirstDutyMember = (members, lastAssignmentState) => {
  // lastAssignmentState から前日の担当者IDを取得 (もしあれば)
  const yesterdayAssignedId = lastAssignmentState?.assignmentDate && lastAssignmentState.assignmentDate !== formatInTimeZone(new Date(), timeZone, 'yyyy-MM-dd') // 日付が変わっていたら考慮しない方が安全かも？要件次第
    ? lastAssignmentState.currentAssignedMemberId
    : null; // 前日のデータがない or 日付が同じなら考慮しない

  logger.info(`Selecting first member, excluding yesterday's: ${yesterdayAssignedId}`);
  let candidates = members.filter(m => m.memberId !== yesterdayAssignedId);

  if (candidates.length === 0) {
    logger.warn("No candidates after excluding yesterday's member. Considering all members.");
    candidates = [...members];
  }

  // カウント昇順 -> 表示順昇順でソート (従来通り)
  candidates.sort((a, b) => {
    const countA = a.dutyCount || 0; const countB = b.dutyCount || 0;
    if (countA !== countB) return countA - countB;
    const orderA = a.displayOrder ?? Infinity; const orderB = b.displayOrder ?? Infinity;
    if (orderA !== orderB) return orderA - orderB;
    return (a.memberId || '').localeCompare(b.memberId || '');
  });
  logger.info(`First member candidates sorted: ${candidates.map(m => m.memberId).join(', ')}`);

  return candidates[0]; // 最初の候補者
};

// ★ ローテーションリストを作成する関数
const createRotationList = (members) => {
  // カウント昇順 -> 表示順昇順でソート
  const sortedMembers = [...members].sort((a, b) => {
    const countA = a.dutyCount || 0; const countB = b.dutyCount || 0;
    if (countA !== countB) return countA - countB;
    const orderA = a.displayOrder ?? Infinity; const orderB = b.displayOrder ?? Infinity;
    if (orderA !== orderB) return orderA - orderB;
    return (a.memberId || '').localeCompare(b.memberId || '');
  });
  // メンバーIDの配列を返す
  const rotationList = sortedMembers.map(m => m.memberId);
  logger.info(`Generated rotation list: ${rotationList.join(', ')}`);
  return rotationList;
};

// ★ DynamoDB更新ロジック (カウント+1 と DutyState更新)
const updateInitialDutyData = async (selectedMember, rotationList, todayStr) => {
  const memberId = selectedMember.memberId;
  const currentIndex = rotationList.indexOf(memberId); // rotationList 内でのインデックス

  if (currentIndex === -1) {
    logger.error(`Selected member ${memberId} not found in generated rotation list! Aborting state update.`);
    // カウントアップだけ実行するか、全体をエラーにするか選択
    // ここではカウントアップは実行し、State更新はスキップする
    try {
      const updateMemberCommand = new UpdateCommand({
        TableName: membersTableName,
        Key: { memberId: memberId },
        UpdateExpression: "ADD dutyCount :inc",
        ExpressionAttributeValues: { ':inc': 1 },
        ReturnValues: "UPDATED_NEW", // 更新後の値を取得（ログ用）
      });
      await docClient.send(updateMemberCommand);
      logger.info(`Incremented duty count for ${memberId} but state update skipped.`);
    } catch (error) {
      logger.error(`Error incrementing count for ${memberId}: ${error}`);
      throw error; // カウントアップも失敗したらエラー
    }
    return; // State更新は行わない
  }

  try {
    // 1. 担当者のカウントを+1
    const updateMemberCommand = new UpdateCommand({
      TableName: membersTableName, Key: { memberId: memberId },
      UpdateExpression: "ADD dutyCount :inc", ExpressionAttributeValues: { ':inc': 1 },
      ReturnValues: "UPDATED_NEW",
    });
    const updateResult = await docClient.send(updateMemberCommand);
    logger.info(`Incremented duty count for ${memberId}. New count: ${updateResult.Attributes?.dutyCount}`);

    // 2. DutyStateテーブルを更新 (PutCommandで上書き)
    const putStateCommand = new PutCommand({
      TableName: stateTableName,
      Item: {
        stateId: stateId,
        assignmentDate: todayStr,         // ★ 今日の日付
        rotationList: rotationList,       // ★ 今日のローテーションリスト
        currentListIndex: currentIndex,   // ★ 現在の担当者のインデックス
        currentAssignedMemberId: memberId, // ★ 現在の担当者ID
      },
    });
    await docClient.send(putStateCommand);
    logger.info(`Updated duty state for ${todayStr} with rotation list. Current index: ${currentIndex}, Member: ${memberId}`);

  } catch (error) {
    logger.error(`Error updating initial duty data for ${memberId}: ${error}`);
    throw error;
  }
};


// Slackに日直通知を送信 (ボタン付き)
const sendSlackNotification = async (member, dateStr, members) => {
  const memberId = member.memberId;
  // Slackのメンション形式 <@MEMBER_ID> を使うと通知が飛ぶ
  const mention = memberId.startsWith('U') || memberId.startsWith('W') ? `<@${memberId}>` : (member.memberName || memberId);
  const message = `☀️ 今日 (${dateStr}) の日直は ${mention} さんです！\nよろしくお願いします！`; // ★ 引数の dateStr をそのまま使う
  // ★ メンバーリスト表示用のブロックを作成
  const memberListBlocks = createMemberListBlocks(members);
  try {
    const response = await slackClient.chat.postMessage({
      channel: slackChannelId,
      text: message, // 通知やフォールバック用テキスト
      blocks: [
        {
          "type": "section",
          "text": {
            "type": "mrkdwn",
            "text": message
          }
        },
        {
          "type": "actions",
          "block_id": "duty_actions", // block_idを付けておくと後で識別しやすい
          "elements": [
            {
              "type": "button",
              "text": {
                "type": "plain_text",
                "text": "担当を変更する",
                "emoji": true
              },
              "style": "danger", // 目立たせるためにdanger（任意）
              "action_id": "reselect_duty_action", // 後で使うアクションID
              // valueに再選出時に必要となりそうな情報を含める
              // （今回はシンプルに現在の担当者IDのみ）
              "value": JSON.stringify({ current_member_id: memberId })
            }
          ]
        },
        // ★★★ 作成したメンバーリストブロックを追加 ★★★
        ...memberListBlocks // スプレッド構文で配列を展開して追加
      ]
    });
    logger.info(`Slack notification sent successfully: ${response.ts}`);
    return response.ts;
  } catch (error) {
    logger.error(`Error sending Slack message: ${error.data?.error || error.message}`);
    throw error;
  }
};

// --- Lambdaハンドラー ---
export const handler = async (event, context) => {
  logger.info(`Event received: ${JSON.stringify(event)}`);

  const now = new Date(); // 現在時刻 (UTC)

  // --- 1. 実行日チェック (指定タイムゾーン基準) ---
  if (!isWeekdayInZone(now, timeZone)) {
    const todayStrForLog = formatInTimeZone(now, timeZone, 'yyyy-MM-dd'); // ログ用
    logger.info(`${todayStrForLog} is a weekend or holiday in ${timeZone}. Skipping.`);
    return { statusCode: 200, body: 'Skipped (weekend or holiday)' };
  }

  // ★ DynamoDB保存用/通知メッセージ用の日付文字列 (yyyy-MM-dd) を生成
  const todayStr = formatInTimeZone(now, timeZone, 'yyyy-MM-dd');
  logger.info(`Today is ${todayStr} in ${timeZone}, a weekday. Proceeding...`);

  try {
    // ★ 前日の状態取得と現在のメンバーリスト取得
    const [lastAssignmentState, currentMembers] = await Promise.all([
      getDutyState(), // ★ 名前変更: getDutyState はそのまま
      getAllMembers()
    ]);

    if (currentMembers.length === 0) {
      logger.warn("No members found in DynamoDB. Cannot assign duty.");
      // 必要であればSlackにエラー通知
      await slackClient.chat.postMessage({ channel: slackChannelId, text: "日直担当者を選出できませんでした: メンバーが登録されていません。" });
      return { statusCode: 400, body: 'No members found' };
    }

    // ★ 最初の担当者を選出
    const selectedMember = selectFirstDutyMember(currentMembers, lastAssignmentState);
    if (!selectedMember) {
      logger.error("Failed to select a duty member.");
      await slackClient.chat.postMessage({ channel: slackChannelId, text: "日直担当者を選出できませんでした: 候補者が見つかりません。" });
      return { statusCode: 500, body: 'Failed to select member' };
    }
    logger.info(`First duty member selected: ${selectedMember.memberId}`);

    // ★ 今日のローテーションリストを作成
    const rotationList = createRotationList(currentMembers);

    // ★ DynamoDB更新 (カウント+1 と DutyState更新)
    await updateInitialDutyData(selectedMember, rotationList, todayStr);

    // ★★★ Slack通知前に最新のメンバー情報を再取得 ★★★
    const updatedMembers = await getAllMembers();

    // --- 5. Slackに通知 ---
    await sendSlackNotification(selectedMember, todayStr, updatedMembers);

    return {
      statusCode: 200,
      body: JSON.stringify({
        message: `Successfully assigned duty to ${selectedMember.memberId} and notified Slack.`,
      }),
    };

  } catch (error) {
    logger.error(`Handler error: ${error.message}`);
    // console.error(error); // 詳細なスタックトレース

    // エラー発生をSlackに通知（可能であれば）
    try {
      await slackClient.chat.postMessage({
        channel: slackChannelId,
        text: `日直通知処理でエラーが発生しました: ${error.message}`,
      });
    } catch (slackError) {
      logger.error(`Failed to send error notification to Slack: ${slackError}`);
    }

    return {
      statusCode: 500,
      body: JSON.stringify({
        message: 'Failed to process request',
        error: error.message,
      }),
    };
  }
};
