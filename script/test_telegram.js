import dotenv from 'dotenv';
dotenv.config();

/**
 * Diagnostic & Testing Script for Telegram Bot Integration
 * Verifies your TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID credentials
 * and dispatches a test alert directly to your Telegram chat.
 */
async function testTelegramConnection() {
  const botToken = process.env.TELEGRAM_BOT_TOKEN || process.env.telegram_bot_token;
  const chatId = process.env.TELEGRAM_CHAT_ID || process.env.telgram_chat_id || process.env.telegram_chat_id;

  console.log('='.repeat(65));
  console.log('📡 TELEGRAM BOT CONNECTION DIAGNOSTIC & TEST');
  console.log('='.repeat(65));

  if (!botToken || botToken.trim() === '') {
    console.error('❌ ERROR: TELEGRAM_BOT_TOKEN is missing in .env!');
    console.log('💡 How to fix:');
    console.log('   1. Open Telegram and search for @BotFather');
    console.log('   2. Send /newbot to create a bot and copy the API token');
    console.log('   3. Put it in .env: TELEGRAM_BOT_TOKEN=your_token_here');
    process.exit(1);
  }

  if (!chatId || chatId.trim() === '') {
    console.error('❌ ERROR: TELEGRAM_CHAT_ID is missing in .env!');
    console.log('💡 How to fix:');
    console.log('   1. Start your bot in Telegram by sending /start');
    console.log('   2. Open @userinfobot to get your Chat ID (or check getUpdates)');
    console.log('   3. Put it in .env: TELEGRAM_CHAT_ID=your_chat_id_here');
    process.exit(1);
  }

  console.log(`[INFO] Bot Token : ${botToken.slice(0, 8)}...${botToken.slice(-4)}`);
  console.log(`[INFO] Chat ID   : ${chatId}`);
  console.log('[*] Testing connection with Telegram API (getMe)...');

  try {
    // 1. Validate Bot Token using getMe
    const meRes = await fetch(`https://api.telegram.org/bot${botToken}/getMe`);
    const meData = await meRes.json();

    if (!meRes.ok || !meData.ok) {
      console.error(`\n❌ Failed to authenticate bot:`, meData.description || 'Unknown error');
      console.log('👉 Please check whether your TELEGRAM_BOT_TOKEN is copied correctly.');
      process.exit(1);
    }

    console.log(`✅ Bot Authenticated: @${meData.result.username} (${meData.result.first_name})`);

    // 2. Dispatch a Test Alert Message
    console.log('\n[*] Sending test alert message to Telegram chat...');
    const message = `🛡️ *SUPABASE SENTINEL — TELEGRAM CONNECTED* 🛡️\n\n`
      + `✅ *Status:* Connection Successful\n`
      + `🕒 *Timestamp:* ${new Date().toISOString()}\n`
      + `📍 *Node Environment:* ${process.env.NODE_ENV || 'development'}\n\n`
      + `_Your Telegram alert integration is ready to receive database threat alerts._`;

    const sendRes = await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: chatId,
        text: message,
        parse_mode: 'Markdown'
      })
    });

    const sendData = await sendRes.json();

    if (!sendRes.ok || !sendData.ok) {
      console.error(`\n❌ Failed to send message:`, sendData.description || 'Unknown error');
      if (sendData.description?.includes('chat not found') || sendData.description?.includes('bot was blocked')) {
        console.log('\n💡 Tip: Make sure you have opened a chat with your bot and clicked START (/start) before running this.');
      }
      process.exit(1);
    }

    console.log('✅ Test alert message delivered successfully!');
    console.log(`   Message ID: ${sendData.result.message_id}`);
    console.log(`   Target Chat: ${sendData.result.chat.username || sendData.result.chat.id}`);
    console.log('='.repeat(65));
    console.log('🎉 TELEGRAM INTEGRATION IS WORKING PERFECTLY!');
    console.log('='.repeat(65));

  } catch (err) {
    console.error('\n❌ Network or API error occurred:', err.message);
    process.exit(1);
  }
}

testTelegramConnection();
