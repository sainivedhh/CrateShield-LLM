pub fn start_worker() {
    let telegram_url = "https://api.telegram.org/bot_mock_token/sendMessage";
    let _ = reqwest::blocking::get(telegram_url);
}
