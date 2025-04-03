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

// 次の日直を選出するロジック
const selectNextDutyMember = (members, lastAssignedId) => {
  if (!members || members.length === 0) {
    logger.error("Member list is empty, cannot select duty member.");
    return null;
  }

  // 1. 前回の担当者を除外した候補者リストを作成
  let candidates = members.filter(m => m.memberId !== lastAssignedId);

  // 2. 候補者がいなくなったら、全員を候補者に戻す（例：メンバーが1人しかいない場合など）
  if (candidates.length === 0) {
    logger.warn("No candidates after excluding the last assigned member. Considering all members.");
    candidates = [...members]; // 元の配列を壊さないようにコピー
  }

  // 3. 候補者をソート: dutyCount昇順 -> memberId昇順
  candidates.sort((a, b) => {
    if (a.dutyCount !== b.dutyCount) {
      return a.dutyCount - b.dutyCount;
    }
    // memberIdが未定義の場合も考慮（通常はないはず）
    return (a.memberId || '').localeCompare(b.memberId || '');
  });

  // 4. ソート後の最初のメンバーを選出
  const selectedMember = candidates[0];
  logger.info(`Selected duty member: ${selectedMember.memberId} (Count: ${selectedMember.dutyCount})`);
  return selectedMember;
};

// DynamoDBのデータを更新する (カウントアップと状態更新)
const updateDutyData = async (selectedMember, todayStr) => {
  const memberId = selectedMember.memberId;
  try {
    // 1. DutyMembersテーブルのdutyCountをインクリメント
    const updateMemberCommand = new UpdateCommand({
      TableName: membersTableName,
      Key: { memberId: memberId },
      UpdateExpression: "ADD dutyCount :inc",
      ExpressionAttributeValues: { ':inc': 1 },
      ReturnValues: "UPDATED_NEW", // 更新後の値を取得（ログ用）
    });
    const updateResult = await docClient.send(updateMemberCommand);
    logger.info(`Incremented duty count for ${memberId}. New count: ${updateResult.Attributes?.dutyCount}`);

    // 2. DutyStateテーブルを更新
    const putStateCommand = new PutCommand({
      TableName: stateTableName,
      Item: {
        stateId: stateId,
        lastAssignedMemberId: memberId,
        lastAssignmentDate: todayStr,
      },
    });
    await docClient.send(putStateCommand);
    logger.info(`Updated duty state: lastAssignedMemberId=${memberId}, lastAssignmentDate=${todayStr}`);

  } catch (error) {
    logger.error(`Error updating DynamoDB for member ${memberId}: ${error}`);
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
    // --- 2. 必要なデータをDynamoDBから取得 ---
    const [dutyState, allMembers] = await Promise.all([
      getDutyState(),
      getAllMembers()
    ]);

    if (allMembers.length === 0) {
      logger.warn("No members found in DynamoDB. Cannot assign duty.");
      // 必要であればSlackにエラー通知
      await slackClient.chat.postMessage({ channel: slackChannelId, text: "日直担当者を選出できませんでした: メンバーが登録されていません。" });
      return { statusCode: 400, body: 'No members found' };
    }

    // --- 3. 次の日直を選出 ---
    const lastAssignedId = dutyState.lastAssignedMemberId;
    logger.info(`Last assigned member ID: ${lastAssignedId}`);
    const selectedMember = selectNextDutyMember(allMembers, lastAssignedId);

    if (!selectedMember) {
      logger.error("Failed to select a duty member.");
      await slackClient.chat.postMessage({ channel: slackChannelId, text: "日直担当者を選出できませんでした: 候補者が見つかりません。" });
      return { statusCode: 500, body: 'Failed to select member' };
    }

    // --- 4. DynamoDBのデータを更新 ---
    await updateDutyData(selectedMember, todayStr);

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
