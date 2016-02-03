x = int(input("x eingeben"))
e = input("e eingeben")
m = int(input("m eingeben"))
print("berechne", x, "^", e, "mod", m)
e_bin = bin(int(e))[2:]
print(e, "=", e_bin)
r = x
e_c = 1
print(r)
for s in e_bin[1::]:
    r = (r*r )% m
    e_c *= 2
    print("s:", s, "exp: r\t",r, "e:", e_c)
    if s == "1":
        r = r * x % m
        e_c += 1
        print("mul: r\t\t",r, "e:", e_c)
