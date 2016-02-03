import requests

s =  requests.Session()

s.get("https://c.iceqll.eu/rookies/chals/code/tworegex.php?regex=flag%")

flag{\w{27}}
