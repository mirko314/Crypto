import requests
import re
cook = []
s =  requests.Session()
for i in range(4):
    req = s.get("https://c.iceqll.eu/rookies/chals/code/captcha3.php")
    print(req.text)
    mat = re.search('(\d+)\s*(\+|\-|\%|\*|\^)\s*(\d+)', req.text)
    print(mat.group(0))
    print(mat.group(1))
    if mat.group(2) =="+":
        sol = int(mat.group(1)) + int(mat.group(3))

    if mat.group(2) =="-":
        sol = int(mat.group(1)) - int(mat.group(3))

    if mat.group(2) =="*":
        sol = int(mat.group(1))  * int(mat.group(3))

    if mat.group(2) =="%":
        sol = int(mat.group(1)) % int(mat.group(3))
    if mat.group(2) == "^":
        sol = "-1"
    print(str(sol))
    print("flag=1&captcha=" + str(sol))
    res2 = s.post("https://c.iceqll.eu/rookies/chals/code/captcha3.php", {"flag": "1", "captcha": str(sol)})
    print(res2)
    print(res2.text)
