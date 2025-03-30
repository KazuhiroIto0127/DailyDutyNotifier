import { WebClient } from '@slack/web-api';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, ScanCommand } from '@aws-sdk/lib-dynamodb'; // ScanCommand をインポート


// --- 設定 ---
const logger = console; // Lambdaの標準ロガー
const region = process.env.AWS_REGION || 'ap-northeast-1'; // Lambdaが実行されるリージョン
const slackToken = process.env.SLACK_BOT_TOKEN;
const slackChannelId = process.env.SLACK_CHANNEL_ID;
const membersTableName = process.env.MEMBERS_TABLE_NAME;

// 環境変数が設定されているか基本的なチェック
if (!slackToken || !slackChannelId || !membersTableName) {
  logger.error('Error: Required environment variables (SLACK_BOT_TOKEN, SLACK_CHANNEL_ID, MEMBERS_TABLE_NAME) are not set.');
  // エラーを投げるか、早期リターン
  throw new Error('Missing required environment variables.');
}

// AWS SDK クライアントの初期化
const dynamoClient = new DynamoDBClient({ region });
const docClient = DynamoDBDocumentClient.from(dynamoClient);

// Slack Web API クライアントの初期化
const slackClient = new WebClient(slackToken);

const getAllMembers = async () => {
  const command = new ScanCommand({ // ★ ScanCommandを使用
    TableName: membersTableName,
    // 必要であれば取得する属性を指定 (今回は全部取得)
    // ProjectionExpression: "memberId, memberName, dutyCount",
  });

  try {
    const { Items } = await docClient.send(command);
    logger.info(`Successfully scanned ${Items?.length || 0} members from ${membersTableName}`);
    return Items || []; // Itemsがundefinedの場合も空配列を返す
  } catch (error) {
    logger.error(`Error scanning DynamoDB table ${membersTableName}: ${error}`);
    throw error; // エラーを再スローしてハンドラーで捕捉
  }
};


// --- Lambdaハンドラー ---
export const handler = async (event, context) => {
  logger.info(`Event received: ${JSON.stringify(event)}`);

  // --- Slackへのメッセージ投稿処理 ---
  try {
    // --- 1. DynamoDBからメンバーリストを取得 ---
    const members = await getAllMembers();

    // --- 2. Slackに送信するメッセージを作成 ---
    let messageText = "現在のメンバーと担当回数:\n";
    if (members.length === 0) {
      messageText += "メンバーデータが見つかりません。";
    } else {
      // 取得したメンバー情報を整形
      members.sort((a, b) => (a.memberName || '').localeCompare(b.memberName || '')); // 名前順にソート（任意）
      members.forEach(member => {
        // SlackのメンバーID形式 <@Uxxxx> でメンションしたい場合
        // const slackMention = member.memberId.startsWith('U') ? `<@${member.memberId}>` : member.memberName;
        const memberName = member.memberName || member.memberId; // 名前がない場合はIDを表示
        messageText += `- ${memberName}: ${member.dutyCount || 0} 回\n`;
      });
    }

    // --- 3. Slackにメッセージを送信 ---
    logger.info(`Sending message to channel ${slackChannelId}...`);
    const result = await slackClient.chat.postMessage({
      channel: slackChannelId,
      text: messageText, // 整形したテキストを送信
    });

    logger.info(`Message sent successfully: ${result.ts}`);

    return {
      statusCode: 200,
      body: JSON.stringify({
        message: 'Member list sent successfully!',
        timestamp: result.ts,
      }),
    };

  } catch (error) {
    // DynamoDBアクセスエラーやSlack送信エラーをここで捕捉
    logger.error(`Handler error: ${error.message}`);
    // console.error(error); // 詳細なスタックトレースが必要な場合

    // エラー発生時にもSlackに通知を送る（任意）
    try {
      await slackClient.chat.postMessage({
        channel: slackChannelId,
        text: `エラーが発生しました: ${error.message}`,
      });
    } catch (slackError) {
      logger.error(`Failed to send error message to Slack: ${slackError}`);
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
