import { WebClient } from '@slack/web-api';

// --- 設定 ---
const logger = console; // Lambdaの標準ロガー
const slackToken = process.env.SLACK_BOT_TOKEN;
const slackChannelId = process.env.SLACK_CHANNEL_ID;

// 環境変数が設定されているか基本的なチェック
if (!slackToken || !slackChannelId) {
  logger.error('Error: SLACK_BOT_TOKEN or SLACK_CHANNEL_ID environment variable is not set.');
  // 実際の運用では、ここでエラーをthrowするか、処理を中断するべき
}

// Slack Web API クライアントの初期化
const slackClient = new WebClient(slackToken);

// --- Lambdaハンドラー ---
export const handler = async (event, context) => {
  logger.info(`Event received: ${JSON.stringify(event)}`);

  // 送信するメッセージ
  const messageText = "Lambdaからのテストメッセージです！ (Node.js)";

  // --- Slackへのメッセージ投稿処理 ---
  try {
    logger.info(`Sending message to channel ${slackChannelId}...`);
    const result = await slackClient.chat.postMessage({
      channel: slackChannelId,
      text: messageText,
      // 必要であればblocksなども追加可能
      // blocks: [
      //  {
      //      "type": "section",
      //      "text": {
      //          "type": "mrkdwn",
      //          "text": messageText
      //      }
      //  }
      // ]
    });

    logger.info(`Message sent successfully: ${result.ts}`); // tsはメッセージのタイムスタンプ

    return {
      statusCode: 200,
      body: JSON.stringify({
        message: 'Message sent successfully!',
        timestamp: result.ts,
      }),
    };

  } catch (error) {
    logger.error(`Error sending Slack message: ${error.data?.error || error.message}`);
    // SlackApiErrorの場合、error.data に詳細が含まれることが多い
    // console.error(error); // 詳細なエラー内容を出力したい場合

    return {
      statusCode: 500,
      body: JSON.stringify({
        message: 'Failed to send message',
        error: error.data?.error || error.message,
      }),
    };
  }
};
