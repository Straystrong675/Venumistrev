import os,json,urllib,httpx,certifi,base64
from capmonster_python import HCaptchaTask
from random import randint,choice
from time import sleep
from colorama import Fore

if os.name == 'nt':
	os.system("cls")
else:
	os.system("clear")

settings = open('config.json')
config = json.load(settings)

if config['proxy'] != "":
	proxies = { "all://": f"http://{config['proxy']}" }
else:
	proxies = None

print(f'''{Fore.LIGHTRED_EX}
 ░█▀█░█▀▄░█░█░█▀█░█▀█░█▀▀░█▀▀░█▀▄░░░▀▀█░█▀█░▀█▀░█▀█░█▀▀░█▀▄
 ░█▀█░█░█░▀▄▀░█▀█░█░█░█░░░█▀▀░█░█░░░░░█░█░█░░█░░█░█░█▀▀░█▀▄
 ░▀░▀░▀▀░░░▀░░▀░▀░▀░▀░▀▀▀░▀▀▀░▀▀░░░░▀▀░░▀▀▀░▀▀▀░▀░▀░▀▀▀░▀░▀ {Fore.RESET}v5 ($ffe)\n''')

tokens_type = input(f"{Fore.RED} Token Type (combo/token): {Fore.RESET}")
debug = input(f"{Fore.RED} Debug (y/N): {Fore.RESET}").lower()

if tokens_type.lower() != "combo":
    tokens = open("tokens.txt", 'r').read().splitlines()
    total_token = len(tokens)
else:
    tokens = open("tokens.txt", "r").read()
    total_token = len(tokens.splitlines())

invite_code = input(f"{Fore.RED} Discord Invite Code (not link): {Fore.RESET}")
min_timeout = int(input(f"{Fore.RED} Min Timeout (0): {Fore.RESET}"))
max_timeout = int(input(f"{Fore.RED} Max Timeout (3): {Fore.RESET}"))
emoji_bypass = input(f"{Fore.RED} Emoji React (yes/no): {Fore.RESET}")

if emoji_bypass == "yes":
	channel_id = int(input(f"{Fore.RED} Channel ID: {Fore.RESET}"))
	message_id = int(input(f"{Fore.RED} Message ID: {Fore.RESET}"))
	emoji_type = input(f"{Fore.RED} Emoji type (discord/nitro): {Fore.RESET}")

	if emoji_type == "discord":
		emoji_converted = input(f"{Fore.RED} Emoji (https://emojis.wiki/discord/) (https://www.urlencoder.io/): {Fore.RESET}")
	elif emoji_type == "nitro":
		emoji = input(f"{Fore.RED} Nitro (emojiname:data-id) {Fore.RESET}")
		emoji_converted = urllib.parse.quote_plus(emoji)

print(f"{Fore.YELLOW}\n [!] Loaded {total_token} Tokens.\n")

while True:
    try:
        response = httpx.get("https://discord-user-api.cf/api/v1/properties/web", proxies=proxies).json()
        chrome_user_agent = response['chrome_user_agent']
        chrome_version = response['chrome_version']
        client_build_number = response['client_build_number']
        if debug == "y":
            print(f"\n{Fore.YELLOW} [DEBUG] Fetching Browser Info:{Fore.LIGHTBLACK_EX}\n\n - UserAgent: {chrome_user_agent}\n - Version: {chrome_version}\n - Build Number: {client_build_number}{Fore.RESET}\n")
        break
    except:
        pass

def randomized_xsuper():
	locales = ["af", "af-NA", "af-ZA", "agq", "agq-CM", "ak", "ak-GH", "am", "am-ET", "ar", "ar-001", "ar-AE", "ar-BH", "ar-DJ", "ar-DZ", "ar-EG", "ar-EH", "ar-ER", "ar-IL", "ar-IQ", "ar-JO", "ar-KM", "ar-KW", "ar-LB", "ar-LY", "ar-MA", "ar-MR", "ar-OM", "ar-PS", "ar-QA", "ar-SA", "ar-SD", "ar-SO", "ar-SS", "ar-SY", "ar-TD", "ar-TN", "ar-YE", "as", "as-IN", "asa", "asa-TZ", "ast", "ast-ES", "az", "az-Cyrl", "az-Cyrl-AZ", "az-Latn", "az-Latn-AZ", "bas", "bas-CM", "be", "be-BY", "bem", "bem-ZM", "bez", "bez-TZ", "bg", "bg-BG", "bm", "bm-ML", "bn", "bn-BD", "bn-IN", "bo", "bo-CN", "bo-IN", "br", "br-FR", "brx", "brx-IN", "bs", "bs-Cyrl", "bs-Cyrl-BA", "bs-Latn", "bs-Latn-BA", "ca", "ca-AD", "ca-ES", "ca-FR", "ca-IT", "ccp", "ccp-BD", "ccp-IN", "ce", "ce-RU", "cgg", "cgg-UG", "chr", "chr-US", "ckb", "ckb-IQ", "ckb-IR", "cs", "cs-CZ", "cy", "cy-GB", "da", "da-DK", "da-GL", "dav", "dav-KE", "de", "de-AT", "de-BE", "de-CH", "de-DE", "de-IT", "de-LI", "de-LU", "dje", "dje-NE", "dsb", "dsb-DE", "dua", "dua-CM", "dyo", "dyo-SN", "dz", "dz-BT", "ebu", "ebu-KE", "ee", "ee-GH", "ee-TG", "el", "el-CY", "el-GR", "en", "en-001", "en-150", "en-AG", "en-AI", "en-AS", "en-AT", "en-AU", "en-BB", "en-BE", "en-BI", "en-BM", "en-BS", "en-BW", "en-BZ", "en-CA", "en-CC", "en-CH", "en-CK", "en-CM", "en-CX", "en-CY", "en-DE", "en-DG", "en-DK", "en-DM", "en-ER", "en-FI", "en-FJ", "en-FK", "en-FM", "en-GB", "en-GD", "en-GG", "en-GH", "en-GI", "en-GM", "en-GU", "en-GY", "en-HK", "en-IE", "en-IL", "en-IM", "en-IN", "en-IO", "en-JE", "en-JM", "en-KE", "en-KI", "en-KN", "en-KY", "en-LC", "en-LR", "en-LS", "en-MG", "en-MH", "en-MO", "en-MP", "en-MS", "en-MT", "en-MU", "en-MW", "en-MY", "en-NA", "en-NF", "en-NG", "en-NL", "en-NR", "en-NU", "en-NZ", "en-PG", "en-PH", "en-PK", "en-PN", "en-PR", "en-PW", "en-RW", "en-SB", "en-SC", "en-SD", "en-SE", "en-SG", "en-SH", "en-SI", "en-SL", "en-SS", "en-SX", "en-SZ", "en-TC", "en-TK", "en-TO", "en-TT", "en-TV", "en-TZ", "en-UG", "en-UM", "en-US", "en-US-POSIX", "en-VC", "en-VG", "en-VI", "en-VU", "en-WS", "en-ZA", "en-ZM", "en-ZW", "eo", "es", "es-419", "es-AR", "es-BO", "es-BR", "es-BZ", "es-CL", "es-CO", "es-CR", "es-CU", "es-DO", "es-EA", "es-EC", "es-ES", "es-GQ", "es-GT", "es-HN", "es-IC", "es-MX", "es-NI", "es-PA", "es-PE", "es-PH", "es-PR", "es-PY", "es-SV", "es-US", "es-UY", "es-VE", "et", "et-EE", "eu", "eu-ES", "ewo", "ewo-CM", "fa", "fa-AF", "fa-IR", "ff", "ff-CM", "ff-GN", "ff-MR", "ff-SN", "fi", "fi-FI", "fil", "fil-PH", "fo", "fo-DK", "fo-FO", "fr", "fr-BE", "fr-BF", "fr-BI", "fr-BJ", "fr-BL", "fr-CA", "fr-CD", "fr-CF", "fr-CG", "fr-CH", "fr-CI", "fr-CM", "fr-DJ", "fr-DZ", "fr-FR", "fr-GA", "fr-GF", "fr-GN", "fr-GP", "fr-GQ", "fr-HT", "fr-KM", "fr-LU", "fr-MA", "fr-MC", "fr-MF", "fr-MG", "fr-ML", "fr-MQ", "fr-MR", "fr-MU", "fr-NC", "fr-NE", "fr-PF", "fr-PM", "fr-RE", "fr-RW", "fr-SC", "fr-SN", "fr-SY", "fr-TD", "fr-TG", "fr-TN", "fr-VU", "fr-WF", "fr-YT", "fur", "fur-IT", "fy", "fy-NL", "ga", "ga-IE", "gd", "gd-GB", "gl", "gl-ES", "gsw", "gsw-CH", "gsw-FR", "gsw-LI", "gu", "gu-IN", "guz", "guz-KE", "gv", "gv-IM", "ha", "ha-GH", "ha-NE", "ha-NG", "haw", "haw-US", "he", "he-IL", "hi", "hi-IN", "hr", "hr-BA", "hr-HR", "hsb", "hsb-DE", "hu", "hu-HU", "hy", "hy-AM", "id", "id-ID", "ig", "ig-NG", "ii", "ii-CN", "is", "is-IS", "it", "it-CH", "it-IT", "it-SM", "it-VA", "ja", "ja-JP", "jgo", "jgo-CM", "jmc", "jmc-TZ", "ka", "ka-GE", "kab", "kab-DZ", "kam", "kam-KE", "kde", "kde-TZ", "kea", "kea-CV", "khq", "khq-ML", "ki", "ki-KE", "kk", "kk-KZ", "kkj", "kkj-CM", "kl", "kl-GL", "kln", "kln-KE", "km", "km-KH", "kn", "kn-IN", "ko", "ko-KP", "ko-KR", "kok", "kok-IN", "ks", "ks-IN", "ksb", "ksb-TZ", "ksf", "ksf-CM", "ksh", "ksh-DE", "kw", "kw-GB", "ky", "ky-KG", "lag", "lag-TZ", "lb", "lb-LU", "lg", "lg-UG", "lkt", "lkt-US", "ln", "ln-AO", "ln-CD", "ln-CF", "ln-CG", "lo", "lo-LA", "lrc", "lrc-IQ", "lrc-IR", "lt", "lt-LT", "lu", "lu-CD", "luo", "luo-KE", "luy", "luy-KE", "lv", "lv-LV", "mas", "mas-KE", "mas-TZ", "mer", "mer-KE", "mfe", "mfe-MU", "mg", "mg-MG", "mgh", "mgh-MZ", "mgo", "mgo-CM", "mk", "mk-MK", "ml", "ml-IN", "mn", "mn-MN", "mr", "mr-IN", "ms", "ms-BN", "ms-MY", "ms-SG", "mt", "mt-MT", "mua", "mua-CM", "my", "my-MM", "mzn", "mzn-IR", "naq", "naq-NA", "nb", "nb-NO", "nb-SJ", "nd", "nd-ZW", "nds", "nds-DE", "nds-NL", "ne", "ne-IN", "ne-NP", "nl", "nl-AW", "nl-BE", "nl-BQ", "nl-CW", "nl-NL", "nl-SR", "nl-SX", "nmg", "nmg-CM", "nn", "nn-NO", "nnh", "nnh-CM", "nus", "nus-SS", "nyn", "nyn-UG", "om", "om-ET", "om-KE", "or", "or-IN", "os", "os-GE", "os-RU", "pa", "pa-Arab", "pa-Arab-PK", "pa-Guru", "pa-Guru-IN", "pl", "pl-PL", "ps", "ps-AF", "pt", "pt-AO", "pt-BR", "pt-CH", "pt-CV", "pt-GQ", "pt-GW", "pt-LU", "pt-MO", "pt-MZ", "pt-PT", "pt-ST", "pt-TL", "qu", "qu-BO", "qu-EC", "qu-PE", "rm", "rm-CH", "rn", "rn-BI", "ro", "ro-MD", "ro-RO", "rof", "rof-TZ", "ru", "ru-BY", "ru-KG", "ru-KZ", "ru-MD", "ru-RU", "ru-UA", "rw", "rw-RW", "rwk", "rwk-TZ", "sah", "sah-RU", "saq", "saq-KE", "sbp", "sbp-TZ", "se", "se-FI", "se-NO", "se-SE", "seh", "seh-MZ", "ses", "ses-ML", "sg", "sg-CF", "shi", "shi-Latn", "shi-Latn-MA", "shi-Tfng", "shi-Tfng-MA", "si", "si-LK", "sk", "sk-SK", "sl", "sl-SI", "smn", "smn-FI", "sn", "sn-ZW", "so", "so-DJ", "so-ET", "so-KE", "so-SO", "sq", "sq-AL", "sq-MK", "sq-XK", "sr", "sr-Cyrl", "sr-Cyrl-BA", "sr-Cyrl-ME", "sr-Cyrl-RS", "sr-Cyrl-XK", "sr-Latn", "sr-Latn-BA", "sr-Latn-ME", "sr-Latn-RS", "sr-Latn-XK", "sv", "sv-AX", "sv-FI", "sv-SE", "sw", "sw-CD", "sw-KE", "sw-TZ", "sw-UG", "ta", "ta-IN", "ta-LK", "ta-MY", "ta-SG", "te", "te-IN", "teo", "teo-KE", "teo-UG", "tg", "tg-TJ", "th", "th-TH", "ti", "ti-ER", "ti-ET", "to", "to-TO", "tr", "tr-CY", "tr-TR", "tt", "tt-RU", "twq", "twq-NE", "tzm", "tzm-MA", "ug", "ug-CN", "uk", "uk-UA", "ur", "ur-IN", "ur-PK", "uz", "uz-Arab", "uz-Arab-AF", "uz-Cyrl", "uz-Cyrl-UZ", "uz-Latn", "uz-Latn-UZ", "vai", "vai-Latn", "vai-Latn-LR", "vai-Vaii", "vai-Vaii-LR", "vi", "vi-VN", "vun", "vun-TZ", "wae", "wae-CH", "wo", "wo-SN", "xog", "xog-UG", "yav", "yav-CM", "yi", "yi-001", "yo", "yo-BJ", "yo-NG", "yue", "yue-Hans", "yue-Hans-CN", "yue-Hant", "yue-Hant-HK", "zgh", "zgh-MA", "zh", "zh-Hans", "zh-Hans-CN", "zh-Hans-HK", "zh-Hans-MO", "zh-Hans-SG", "zh-Hant", "zh-Hant-HK", "zh-Hant-MO", "zh-Hant-TW", "zu", "zu-ZA"]
	xsuper = {"os":"Windows","browser":"Chrome","device":"","system_locale":f"{choice(locales)}","browser_user_agent":f"{chrome_user_agent}","browser_version":f"{chrome_version}","os_version":"10","referrer":"","referring_domain":"","referrer_current":"","referring_domain_current":"","release_channel":"stable","client_build_number":client_build_number,"client_event_source":"null"}
	fixed = json.dumps(xsuper, separators=(',', ':')).encode("utf-8")
	encoded = base64.b64encode(fixed).decode("utf-8")
	if debug == "y":
		print(f"{Fore.YELLOW} [DEBUG] Randomizing and Encoding XSUPER:{Fore.LIGHTBLACK_EX}\n\n ({encoded}){Fore.RESET}\n")
	return encoded

def captcha_bypass(url, key, captcha_rqdata):
	capmonster = HCaptchaTask(config["capmonster"])
	capmonster.set_user_agent(chrome_user_agent)
	task_id = capmonster.create_task(url, key, is_invisible=True, custom_data=captcha_rqdata)
	result = capmonster.join_task_result(task_id)
	response = result.get("gRecaptchaResponse")
	print(f"{Fore.LIGHTGREEN_EX} [+] Captcha solved {Fore.LIGHTBLACK_EX}({response[-32:]}){Fore.RESET}")
	return response

def gen_ciphers():
	ciphers_top = "ECDH+AESGCM:ECDH+CHACHA20:DH+AESGCM"
	ciphers_mid = 'DH+CHACHA20:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:ECDH+HIGH:DH+HIGH:RSA+AESGCM:RSA+AES:RSA+HIGH:!aNULL:!eNULL:!MD5:!3DES'
	cl = ciphers_mid.split(":")
	cl_len = len(cl)
	els = []
	
	for i in range(cl_len):
		idx = randint(0, cl_len-1)
		els.append(cl[idx])
		del cl[idx]
		cl_len-=1

	ciphers2 = ciphers_top+":".join(els)
	if debug == "y":
		print(f"{Fore.YELLOW} [DEBUG] Generating new ciphers:\n\n {Fore.LIGHTBLACK_EX}({ciphers2}){Fore.RESET}\n")
	return ciphers2

while True:
    try:
        server_info = httpx.get(f'https://discord.com/api/v10/invites/{invite_code}', proxies=proxies)
        xcontext = {"location": "Join Guild", "location_guild_id": server_info.json()['guild']['id'], "location_channel_id": server_info.json()['channel']['id'], "location_channel_type": 0}
        if debug == "y":
            print(f"{Fore.YELLOW} [DEBUG] Fetching Server Info: {Fore.LIGHTBLACK_EX}(Guild: {server_info.json()['guild']['id']}) (Channel: {server_info.json()['channel']['id']}){Fore.RESET}")
        fixed_xcontent = json.dumps(xcontext, separators=(',', ':')).encode("utf-8")
        encoded_xcontent = base64.b64encode(fixed_xcontent).decode("utf-8")
        break
    except:
        pass

join = 0

while join < total_token:
	try:

		headers = {
        	'accept': "*/*",
        	'accept-language': 'en-US,en;q=0.9',
        	'origin': 'https://discord.com',
        	'referer': 'https://discord.com/channels/@me',
        	'user-agent': chrome_user_agent,
        	'x-super-properties': randomized_xsuper()
		}

		context = httpx.create_ssl_context()
		context.load_verify_locations(cafile=certifi.where())
		context.set_alpn_protocols(["h2"])
		context.minimum_version.MAXIMUM_SUPPORTED
		CIPHERS = gen_ciphers()
		context.set_ciphers(CIPHERS)
		client = httpx.Client(http2=True, verify=context, proxies=proxies, timeout=20)

		if tokens_type.lower() != "combo":
			token = tokens[join]
		else:
			token = tokens.split()[join].split(':')[2]

		headers["authorization"] = token
		client.get(f'https://discord.com/api/v10/invites/{invite_code}', headers=headers, params={'inputValue': invite_code, 'with_counts': 'true', 'with_expiration': 'true'})
		headers["x-context-properties"] = encoded_xcontent
		response = client.post(f"https://discord.com/api/v10/invites/{invite_code}", json={}, headers=headers)
		if response.status_code == 400:
			print(f"{Fore.YELLOW} [!] Captcha {token[:50]}****** detected! Solving.. {Fore.RESET}({Fore.LIGHTBLACK_EX}{response.json()['captcha_sitekey']}{Fore.RESET})")
			client.get(f'https://discord.com/api/v10/invites/{invite_code}', headers=headers, params={'inputValue': invite_code, 'with_counts': 'true', 'with_expiration': 'true'})
			response_captcha = client.post(f"https://discord.com/api/v10/invites/{invite_code}", json={"captcha_key": captcha_bypass("https://discord.com", f"{response.json()['captcha_sitekey']}", response.json()['captcha_rqdata']), 'captcha_rqtoken': response.json()['captcha_rqtoken']}, headers=headers)
			if response_captcha.status_code == 200:
				print(f"{Fore.LIGHTGREEN_EX} [+] {token[:50]}****** joined! {Fore.RESET}({Fore.LIGHTBLACK_EX}{invite_code}{Fore.RESET})")
				body = response_captcha.json()
				guild_id = body['guild']['id']
				if 'show_verification_form' in body:
					get_rules = client.get(f"https://discord.com/api/v10/guilds/{guild_id}/member-verification?with_guild=false", headers=headers).json()
					response2 = client.put(f"https://discord.com/api/v10/guilds/{guild_id}/requests/@me", headers=headers, json=get_rules)
					if response2.status_code == 201 or response2.status_code == 204:
						print(f"{Fore.LIGHTGREEN_EX} [+] {token[:50]}****** accepted the rules!{Fore.RESET}")
					else:
						print(f"{Fore.LIGHTRED_EX} [!] {token[:50]}****** not accepted the rules! {Fore.RESET}({Fore.LIGHTBLACK_EX}{response2.content}{Fore.RESET})")
				if emoji_bypass == "yes":
					response3 = client.put(f"https://discord.com/api/v10/channels/{channel_id}/messages/{message_id}/reactions/{emoji_converted}/%40me", headers=headers)
					if response3.status_code == 201 or response3.status_code == 204:
						print(f"{Fore.LIGHTGREEN_EX} [+] {token[:50]}****** reacted to the emoji!{Fore.RESET}")
					else:
						print(f"{Fore.LIGHTRED_EX} [!] {token[:50]}****** can't reacted to the emoji! {Fore.RESET}({Fore.LIGHTBLACK_EX}{response3.content}{Fore.RESET})")

		elif response.status_code == 200:
			print(f"{Fore.LIGHTGREEN_EX} [+] {token[:50]}****** joined! {Fore.RESET}({Fore.LIGHTBLACK_EX}{invite_code}{Fore.RESET})")
			body = response.json()
			guild_id = body['guild']['id']
			if 'show_verification_form' in body:
				get_rules = client.get(f"https://discord.com/api/v10/guilds/{guild_id}/member-verification?with_guild=false", headers=headers).json()
				response2 = client.put(f"https://discord.com/api/v10/guilds/{guild_id}/requests/@me", headers=headers, json=get_rules)
				if response2.status_code == 201 or response2.status_code == 204:
					print(f"{Fore.LIGHTGREEN_EX} [+] {token[:50]}****** accepted the rules!{Fore.RESET}")
				else:
					print(f"{Fore.LIGHTRED_EX} [!] {token[:50]}****** not accepted the rules! {Fore.RESET}({Fore.LIGHTBLACK_EX}{response2.content}{Fore.RESET})")
			if emoji_bypass == "yes":
				response3 = client.put(f"https://discord.com/api/v10/channels/{channel_id}/messages/{message_id}/reactions/{emoji_converted}/%40me", headers=headers)
				if response3.status_code == 201 or response3.status_code == 204:
					print(f"{Fore.LIGHTGREEN_EX} [+] {token[:50]}****** reacted to the emoji!{Fore.RESET}")
				else:
					print(f"{Fore.LIGHTRED_EX} [!] {token[:50]}****** can't reacted to the emoji! {Fore.RESET}({Fore.LIGHTBLACK_EX}{response3.content}{Fore.RESET})")
		else:
			print(f"{Fore.LIGHTRED_EX} [!] {token[:50]}****** not joined! {Fore.RESET}({Fore.LIGHTBLACK_EX}{response.content}{Fore.RESET})")
		time = randint(min_timeout, max_timeout)
		print(f"{Fore.LIGHTBLUE_EX} [!] Sleeping for {time} seconds.{Fore.RESET}")
		sleep(time)
		join += 1

	except Exception as err:
		print(f"{Fore.YELLOW} [!] {token[:50]}****** retrying.. {Fore.RESET}({Fore.LIGHTBLACK_EX}{err}{Fore.RESET})\n")
		join = join - 1
		pass

input(f"\n{Fore.BLUE} DONE {Fore.RESET}")
