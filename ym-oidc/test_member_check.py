import sys, types, os, datetime as dt, importlib
for m in ["redis","requests","flask","authlib","authlib.jose"]:
    sys.modules[m]=types.ModuleType(m)
sys.modules["redis"].Redis=types.SimpleNamespace(from_url=lambda *a,**k:None)
f=sys.modules["flask"]
class App:
    def __init__(s,*a): pass
    def route(s,*a,**k): return lambda fn: fn
f.Flask=App
for n in ["abort","jsonify","make_response","redirect","request","session"]: setattr(f,n,None)
class JWK:
    @staticmethod
    def import_key(*a): return None
sys.modules["authlib.jose"].JsonWebKey=JWK; sys.modules["authlib.jose"].jwt=None
os.environ.update(SECRET_KEY="x",YM_SITE_URL="https://m",YM_APP_ID="a",YM_APP_SECRET="b",YM_CLIENT_ID="1",
  OIDC_ISSUER="https://tickets.caves.org/oidc",OIDC_CLIENT_ID="c",OIDC_CLIENT_SECRET="d",REDIRECT_URI="https://t/cb",
  KEY_PATH="/dev/null",PUB_PATH="/dev/null")
sys.path.insert(0,"os.path.dirname(os.path.abspath(__file__))"); y=importlib.import_module("ym_oidc")
T=dt.date(2026,11,1)
def P(t="Regular",exp="2027-03-31T00:00:00",susp=False,flag=True):
    return {"AccountInformation":{"MemberTypeCode":t,"MembershipExpiresDate":exp,"MembershipExpires":flag},"Administration":{"Suspended":susp}}
cases=[
 (P(),"",True,"current"),
 (P(exp="2026-11-01T00:00:00"),"",True,"current"),
 (P(exp="2026-10-31T00:00:00"),"",False,"expired"),
 (P(exp="/Date(1806451200000-0000)/"),"",True,"current"),
 (P(exp="10/1/2026 12:00:00 AM"),"",False,"expired"),
 (P(t="Life",exp="2001-01-01T00:00:00"),"",True,"life"),
 (P(exp="0001-01-01T00:00:00",flag=False),"",True,"no_expiry_date"),
 (P(t="Vendor"),"",False,"type_not_eligible"),
 (P(t=""),"",False,"type_not_eligible"),
 (P(susp=True),"",False,"suspended"),
 ({},"",False,"no_profile"),
]
for prof,c,ok,r in cases:
    got=y._membership_status(prof,c,today=T); assert got[:2]==(ok,r),(prof,got)
assert y._membership_status(P(),"2027-03-31",today=T)[2]["custom_vs_account"]=="same"
assert y._membership_status(P(),"2026-03-31",today=T)[2]["custom_vs_account"]=="differ"
y.MEMBER_GRACE_DAYS=30; assert y._membership_status(P(exp="2026-10-15"),"",today=T)[0]
print("all",len(cases)+3,"cases pass")
