import datetime
import requests
import json
import time

def logp(text):
    # Get the current time
    current_time = datetime.datetime.now()
    # Format and print the current time
    formatted_time = current_time.strftime("%H:%M:%S")
    print(f"[{formatted_time}] {text}")


def log_with_telegram_webhook(message):
    webhook_url = "https://api.telegram.org/bot6702364047:AAHjJzcGFFbuuZx6zwURRgD6OsGw_H5BnHc/sendMessage"
    chat_id = "-4024874032"
    
    payload = {
        "chat_id": chat_id,
        "text": message
    }
    
    try:
        response = requests.post(webhook_url, json=payload)
        response.raise_for_status()
        print("Message logged successfully.")
    except requests.exceptions.RequestException as e:
        print(f"Error logging message: {e}")


def log_to_discord(user, results, entropy):
        print(entropy)
        data = results
        # Now, extract variables
        protocol = data["protocol"]
        udp_srcport = data.get("common_sport", {}).get("udp.srcport", 0)
        tcp_srcport = data.get("common_sport", {}).get("tcp.srcport", 0)

        top_ips = data["top_ips"]
        # Extract just the IP addresses
        ip_list = [ip[0] for ip in top_ips]

        # Join into a comma-separated string
        comma_separated_ips = ", ".join(ip_list)
        anomaly_score = data["anomaly_score"]
        total_ip = data["total_ip"]
        avg_packets_per_ip = data["avg_packets_per_ip"]
        ips_above_avg = len(data["ips_above_avg_packets"])
    
        with open("/root/zux/net_ai/assets/discord.txt") as f:
              text = f.read()  
        text = text.replace("{protocol}", str(protocol)).replace("{top_ips}", str(comma_separated_ips))
        text = text.replace("{udp_srcport}", str(udp_srcport)).replace("{tcp_srcport}", str(tcp_srcport))
        text = text.replace("{anomaly_score}", str(anomaly_score)).replace("{total_ip}", str(total_ip))
        text = text.replace("{avg_packets_per_ip}", str(avg_packets_per_ip)).replace("{ips_above_avg}", str(ips_above_avg))
        text = text.replace("{entropy}", str(entropy)).replace("{user}", str(user))
        data = json.loads(text)    

        url = "https://discord.com/api/webhooks/1234720804407873546/jUJ98MnviUgWjWq8PH3CVLMpVSnbT_u62zHLNuMnD-D-CeZ8zeKUf_MWEo1C61N1cZc1"

        payload = data

        requests.post(url, json=payload)


def live_discord():
    webhook_url = 'https://discord.com/api/webhooks/1374089169600643102/Yvkb_BADpDnXEc22BJb6QUfQdyKN3XQuNFiOAzW40Fckix_SukPV0WkYXFnMu910gawH?wait=true'

    initial_embed = {
        'title': 'Live Stats',
        'description': 'Starting live updates...'
    }
    payload = {'embeds': [initial_embed]}

    try:
        response = requests.post(webhook_url, json=payload)
        response.raise_for_status()
        response_data = response.json()
        message_id = response_data.get('id')
    except Exception as e:
        logp("Error sending initial embed:", e)
        return

    if not message_id:
        logp("No message ID received; cannot update message.")
        return

    webhook_base = webhook_url.split('?')[0] 
    while True:
        try:
            now = time.strftime("%H:%M:%S")
            countdown = 5  # seconds to next update
            with open("/root/zux/net_ai/assets/live.txt") as f:
              text = f.read()  
            text = text.replace("{now}", str(now)).replace("{countdown}", str(countdown))
            data = json.loads(text) 
            payload = data
            update_url = f'{webhook_base}/messages/{message_id}'
            response = requests.patch(update_url, json=payload)
            response.raise_for_status()
        except Exception as e:
            logp(f'Failed to update embed:{e}')

        time.sleep(countdown)


   