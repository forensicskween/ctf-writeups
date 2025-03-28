import re
from rich import print

def custom_shuffle_8b18(k: str, j: int):
    y = len(k)
    o = [k[m] for m in range(y)]

    for m in range(y):
        b = j * (m + 143) + (j % 34726)
        r = j * (m + 91) + (j % 23714)
        v = b % y
        s = r % y
        o[v], o[s] = o[s], o[v]
        j = (b + r) % 4449625

    a = chr(127)
    i = ''
    e = '%'
    q = '#1'
    t = '%'
    h = '#0'
    w = '#'

    result = ''.join(o).replace(e, a).replace(q, t).replace(h, w).split(a)
    return result

def custom_shuffle_5975(o: str, u: int):
    g = len(o)
    t = [o[w] for w in range(g)]

    for w in range(g):
        z = u * (w + 340) + (u % 19375)
        a = u * (w + 556) + (u % 18726)
        h = z % g
        q = a % g
        t[h], t[q] = t[q], t[h]
        u = (z + a) % 5939310

    k = chr(127)
    r = ''
    l = '%'
    i = '#1'
    v = '%'
    e = '#0'
    f = '#'

    result = ''.join(t).replace(l, k).replace(i, v).replace(e, f).split(k)
    return result

def fix_braces_5975(s):
    return re.sub(r"(\{_5975\[\d+\])", r"\1}", s)

def fix_braces_8b18(s):
    return re.sub(r"_8b18\[\d+\]", lambda m: f"{{{m.group(0)}}}", s)


def wrap_5975_tags(s):
    return re.sub(r"(?<!\{)(_5975\[\d+\])(?!\})", r"{\1}", s)


def to_base36(n):
    chars = "0123456789abcdefghijklmnopqrstuvwxyz"
    result = ''
    while n > 0:
        n, r = divmod(n, 36)
        result = chars[r] + result
    return result or '0'

def decode1(o, *args):
    r = list(args)[::-1]
    return ''.join(chr(val - o - 7 - i) for i, val in enumerate(r))

def decode2(o, *args):
    r = list(args)[::-1]
    return ''.join(chr(val - o - 60 - i) for i, val in enumerate(r))

def G():
    part1 = decode1(43, 106, 167, 103, 163, 98)  # character decoding
    part2 = to_base36(1354343).lower()          # base-36
    part3 = ''.join(chr(ord(c) - 13) for c in to_base36(21).lower())  # shift -13
    part4 = to_base36(4).lower()                # base-36
    part5 = ''.join(chr(ord(c) - 39) for c in to_base36(32).lower())  # shift -39
    part6 = ''.join(chr(ord(c) - 13) for c in to_base36(381).lower()) # shift -13
    part7 = decode2(42, 216, 153, 153, 213, 187) # character decoding

    return part1 + part2 + part3 + part4 + part5 + part6 + part7



_8b18 = custom_shuffle_8b18(
    'shfnemBLlerpitrtgt%ld%DmvuFeceaEaladerletdtdtsputpnielEvae%%iansn%eimkei%guLt%d%i%tsv%ds%eltee%ewssmnnvdsaiyrroeesmlc@Feroieoel%bt%lIota',
    3827531
)

_5975 = custom_shuffle_5975('%dimfT%mVlzx%degpatf5bfnrG%6tSiqth5at%easpi0emILmcim%e%/!=eZtnHf%e7cf+3rstO%%.D0i8p3t/Sphryoa%IL0rin%rcAeF6%nsenoYaLeQ5Natp4CrSrCGttUtZrdG%rlxe2poa2rdg=9fQs%&j_of0ButCO tb=r35DyCee8tgaCf=I=%rAQa4fe%ar0aonsGT_v/NgoPouP2%eoe%ue3tl&enTceynCtt4FBs%s/rBsAUEhradnkrstfgd?%t%xeyhcedeTo%olghXMsaocrB3aaDBr5rRa16Cjuct%cOee5lWE_ooo+Ka4%d3TysnehshstepId%%Ieoaycug:i_m=%%mjp0tgaiidoei.prn%sw1d', 4129280);


f_doc = """document[_$_8b18[3]](_$_8b18[14])[_$_8b18[13]](_$_8b18[0], function(e) {
    e[_$_8b18[1]]();
    const emailField = document[_$_8b18[3]](_$_8b18[2]);
    const descriptionField = document[_$_8b18[3]](_$_8b18[4]);
    let isValid = true;
    if (!emailField[_$_8b18[5]]) {
        emailField[_$_8b18[8]][_$_8b18[7]](_$_8b18[6]);
        isValid = false;
        setTimeout(() => {
            return emailField[_$_8b18[8]][_$_8b18[9]](_$_8b18[6])
        }, 500)
    };
    if (!isValid) {
        return
    };
    const emailValue = emailField[_$_8b18[5]];
    const specialKey = emailValue[_$_8b18[11]](_$_8b18[10])[0];
    const desc = parseInt(descriptionField[_$_8b18[5]], 10);
    f(specialKey, desc)
});;""".replace('_$_8b18','_8b18').replace('}',')').replace('{','(')

f_func = """function f(oferkfer, icd) {
    const channel_id = -1002496072246;
    var enc_token = _$_5975[0];
    if (oferkfer === G(_$_5975[1]) && CryptoJS[_$_5975[7]](sequence[_$_5975[6]](_$_5975[5]))[_$_5975[4]](CryptoJS[_$_5975[3]][_$_5975[2]]) === _$_5975[8]) {
        var decrypted = CryptoJS[_$_5975[12]][_$_5975[11]](enc_token, CryptoJS[_$_5975[3]][_$_5975[9]][_$_5975[10]](oferkfer), {
            drop: 192
        })[_$_5975[4]](CryptoJS[_$_5975[3]][_$_5975[9]]);
        var HOST = _$_5975[13] + String[_$_5975[14]](0x2f) + String[_$_5975[14]](0x62) + String[_$_5975[14]](0x6f) + String[_$_5975[14]](0x74) + decrypted;
        var xhr = new XMLHttpRequest();
        xhr[_$_5975[15]] = function() {
            if (xhr[_$_5975[16]] == XMLHttpRequest[_$_5975[17]]) {
                const resp = JSON[_$_5975[10]](xhr[_$_5975[18]]);
                try {
                    const link = resp[_$_5975[20]][_$_5975[19]];
                    window[_$_5975[23]][_$_5975[22]](link)
                } catch (error) {
                    alert(_$_5975[24])
                }
            }
        };
        xhr[_$_5975[29]](_$_5975[25], HOST + String[_$_5975[14]](0x2f) + _$_5975[26] + icd + _$_5975[27] + channel_id + _$_5975[28]);
        xhr[_$_5975[30]](null)
    } else {
        alert(_$_5975[24])
    }
};;""".replace('}',')').replace('{','(').replace('_$_5975','_5975')


str_doc = fix_braces_8b18(f_doc)
str_func = wrap_5975_tags(f_func)

print(f'Document Function')
print(eval(f"f'''{str_doc}'''"))
print('\n\n\n')

print(f'F Function')
print(eval(f"f'''{str_func}'''"))
print('\n\n\n')


sequence=[]
_ead6 = ['\x69\x6E\x70\x75\x74\x5B\x63\x6C\x61\x73\x73\x3D\x63\x62\x5D', '\x71\x75\x65\x72\x79\x53\x65\x6C\x65\x63\x74\x6F\x72\x41\x6C\x6C', '\x6C\x65\x6E\x67\x74\x68', '\x63\x68\x61\x6E\x67\x65', '\x61\x64\x64\x45\x76\x65\x6E\x74\x4C\x69\x73\x74\x65\x6E\x65\x72'];
checkboxes = f'document[{_ead6[1]}]({_ead6[0]})'
l = f'sequence.push(this.id)'
loop_func = f"""for (var i = 0; i < {checkboxes}[{_ead6[2]}]; i++)
    {checkboxes}[i][{_ead6[4]}]({_ead6[3]}, {l})"""

print(f'Loop Function')
print(loop_func)








