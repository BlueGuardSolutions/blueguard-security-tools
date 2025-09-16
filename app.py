# app.py  — BlueGuard Security Tools (one-file Streamlit app)
# Features: Password Strength Checker + Password Generator


import math, re, secrets, string
import streamlit as st

# -------------------- Minimal "CSS" styling --------------------
st.set_page_config(page_title="BlueGuard Security Tools", page_icon="🔐", layout="centered")

st.markdown("""
<style>
/* page width + fonts */
.block-container {max-width: 900px;}
/* sexy cards */
.bg-card {
  border-radius: 18px;
  padding: 22px 20px;
  margin: 8px 0 18px 0;
  background: linear-gradient(180deg, #0f172a 0%, #111827 100%);
  border: 1px solid rgba(59,130,246,.2);
  box-shadow: 0 6px 24px rgba(0,0,0,.25);
  color: #e5e7eb;
}
.bg-chip {
  display:inline-block; padding:4px 10px; border-radius:999px;
  background:#1f2937; border:1px solid rgba(148,163,184,.25); font-size:12px; margin-right:6px
}
.bg-small { color:#94a3b8; font-size: 12px; }
h1, h2, h3 { letter-spacing:.2px }
</style>
""", unsafe_allow_html=True)

st.title("🔐 BlueGuard Security Tools")
st.caption("Password Strength Checker & Generator — runs in your browser. Inputs are not stored.")

# -------------------- Password strength logic --------------------
COMMON = {
    "123456","password","12345678","qwerty","123456789","12345","111111","abc123",
    "password1","admin","letmein","welcome","iloveyou","monkey","dragon","login"
}
SEQUENTIALS = ["abcdefghijklmnopqrstuvwxyz","qwertyuiop","asdfghjkl","zxcvbnm","0123456789"]

def _has_lower(s): return any(c.islower() for c in s)
def _has_upper(s): return any(c.isupper() for c in s)
def _has_digit(s): return any(c.isdigit() for c in s)
def _has_symbol(s): return any(not c.isalnum() for c in s)

def _has_repeats(s, n=3):  # aaa, 1111
    return re.search(rf"(.)\1{{{n-1},}}", s or "") is not None

def _has_sequence(s, window=4):
    low = (s or "").lower()
    for seq in SEQUENTIALS:
        for i in range(len(seq)-window+1):
            chunk = seq[i:i+window]
            if chunk in low or chunk[::-1] in low:
                return True
    return False

def _charset_size(pw: str) -> int:
    size = 0
    if _has_lower(pw): size += 26
    if _has_upper(pw): size += 26
    if _has_digit(pw): size += 10
    if _has_symbol(pw): size += 33
    return max(1, size)

def estimate_entropy_bits(pw: str) -> float:
    if not pw: return 0.0
    return len(pw) * math.log2(_charset_size(pw))

def rate_password(pw: str) -> dict:
    """Return dict: score (0–100), rating, entropy, feedback[list]."""
    fb = []
    if not pw:
        return {"score":0,"rating":"Very Weak","entropy":0.0,"feedback":["Password is empty."]}

    length = len(pw)
    entropy = estimate_entropy_bits(pw)
    base = min(80, int(entropy))
    variety = sum([_has_lower(pw), _has_upper(pw), _has_digit(pw), _has_symbol(pw)])
    base += (variety - 1) * 5  # up to +15

    penalty = 0
    if pw.lower() in COMMON:
        penalty += 40; fb.append("Appears in common-password lists.")
    if length < 8:
        penalty += 25; fb.append("Too short. Use at least 12–14 characters.")
    elif length < 12:
        penalty += 10; fb.append("Longer is stronger: aim for 12–16+ characters.")
    if _has_repeats(pw):    penalty += 10; fb.append("Avoid repeated characters like 'aaa' or '1111'.")
    if _has_sequence(pw):   penalty += 10; fb.append("Avoid keyboard/alphabetical sequences.")
    if variety <= 2:        fb.append("Add upper/lowercase, digits and symbols for variety.")

    score = max(0, min(100, base - penalty))
    if score < 25: rating = "Very Weak"
    elif score < 45: rating = "Weak"
    elif score < 65: rating = "Fair"
    elif score < 85: rating = "Strong"
    else: rating = "Excellent"

    if rating in ("Very Weak","Weak"):
        fb.append("Consider a passphrase of 4–5 random words.")
    if rating != "Excellent" and length < 16:
        fb.append("Target 16+ characters for long-term safety.")

    # dedupe
    seen, tips = set(), []
    for t in fb:
        if t not in seen:
            seen.add(t); tips.append(t)

    return {"score":score, "rating":rating, "entropy":round(entropy,1), "feedback":tips}

# -------------------- Password generator --------------------
AMBIGUOUS = set("O0oIl1|`'\";:,.{}[]()<>")

def build_charset(lower=True, upper=True, digits=True, symbols=True, no_amb=False) -> str:
    chars = ""
    if lower:   chars += string.ascii_lowercase
    if upper:   chars += string.ascii_uppercase
    if digits:  chars += string.digits
    if symbols: chars += "!@#$%^&*_-+=:?/~"
    if no_amb:
        chars = "".join(c for c in chars if c not in AMBIGUOUS)
    return chars

def generate_password(length=16, lower=True, upper=True, digits=True, symbols=True, no_amb=False) -> str:
    if not any([lower,upper,digits,symbols]):
        raise ValueError("Enable at least one character set.")
    if length < max(4, sum([lower,upper,digits,symbols])):
        raise ValueError("Length too short for requested complexity.")
    charset = build_charset(lower,upper,digits,symbols,no_amb)
    pw = [secrets.choice(charset) for _ in range(length)]
    # ensure complexity: replace some positions
    pools = []
    if lower:   pools.append(string.ascii_lowercase)
    if upper:   pools.append(string.ascii_uppercase)
    if digits:  pools.append(string.digits)
    if symbols: pools.append("!@#$%^&*_-+=:?/~")
    for pool in pools:
        idx = secrets.randbelow(len(pw))
        pw[idx] = secrets.choice(pool)
    secrets.SystemRandom().shuffle(pw)
    return "".join(pw)

# -------------------- UI --------------------
left, right = st.columns(2, gap="large")

with left:
    st.subheader("🔎 Password Strength Checker")
    st.markdown('<div class="bg-card">', unsafe_allow_html=True)
    pwd = st.text_input("Enter a password to evaluate", type="password", placeholder="e.g. BlueGuard!2025")
    show_pw = st.checkbox("Show password", value=False)
    if show_pw and pwd:
        st.code(pwd, language=None)

    if pwd:
        res = rate_password(pwd)
        # rating chips
        st.write(
            f'<span class="bg-chip">Rating: <b>{res["rating"]}</b></span>'
            f'<span class="bg-chip">Score: <b>{res["score"]}/100</b></span>'
            f'<span class="bg-chip">Entropy: <b>{res["entropy"]} bits</b></span>',
            unsafe_allow_html=True
        )
        st.progress(res["score"]/100)
        if res["feedback"]:
            st.markdown("**Tips**")
            for tip in res["feedback"]:
                st.write(f"• {tip}")
    else:
        st.markdown('<span class="bg-small">We do not store passwords. Checks are done in your browser session.</span>', unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)

with right:
    st.subheader("⚙️ Password Generator")
    st.markdown('<div class="bg-card">', unsafe_allow_html=True)
    length = st.slider("Length", 8, 64, 16)
    c1, c2 = st.columns(2)
    with c1:
        lower  = st.checkbox("Lowercase", value=True)
        upper  = st.checkbox("Uppercase", value=True)
        digits = st.checkbox("Digits", value=True)
    with c2:
        symbols = st.checkbox("Symbols", value=True)
        no_amb  = st.checkbox("Avoid ambiguous (O/0, l/1, |)", value=False)
    how_many = st.number_input("How many passwords", 1, 20, 3, help="Generate multiple options to pick from.")

    if st.button("Generate"):
        out = []
        for _ in range(how_many):
            out.append(generate_password(length, lower, upper, digits, symbols, no_amb))
        st.write("### Generated passwords")
        for p in out:
            st.code(p)
        st.download_button("Download as .txt", "\n".join(out), file_name="blueguard_passwords.txt")
    st.markdown("</div>", unsafe_allow_html=True)

st.write("---")
st.caption("© BlueGuard Solutions · (02) 7259 8327 · rai@blueguardsolutions.com.au")
