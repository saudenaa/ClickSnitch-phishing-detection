import re
from urllib.parse import urlparse
from collections import Counter

# ---------------- FEATURE EXTRACTION (FULL 87 FEATURES) ----------------
def extract_features_from_url(url):
    parsed = urlparse(url)
    host = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    # Helper functions
    def get_words(text):
        return re.findall(r'[a-zA-Z]+', text)

    def word_stats(words):
        if not words:
            return 0, 0, 0, 0
        lengths = [len(w) for w in words]
        return (
            len(words),
            min(lengths),
            max(lengths),
            sum(lengths)/len(lengths)
        )

    def char_repeat_score(text):
        if len(text) < 2:
            return 0
        counts = Counter(text.lower())
        return max(counts.values()) / len(text)

    # Extract word statistics
    url_words = get_words(url)
    host_words = get_words(host)
    path_words = get_words(path)

    url_wc, shortest_url, longest_url, avg_url = word_stats(url_words)
    host_wc, shortest_host, longest_host, avg_host = word_stats(host_words)
    path_wc, shortest_path, longest_path, avg_path = word_stats(path_words)

    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.top', '.click', '.zip', '.gq']
    brands = ['paypal','google','amazon','microsoft','apple','facebook','bank','chase']
    phish_words = ['verify','account','secure','alert','update','login','confirm','password']

    features = {
        'length_url': len(url),
        'length_hostname': len(host),
        'ip': int(re.match(r'\d+\.\d+\.\d+\.\d+', host) is not None),
        'nb_dots': url.count('.'),
        'nb_hyphens': url.count('-'),
        'nb_at': url.count('@'),
        'nb_qm': url.count('?'),
        'nb_and': url.count('&'),
        'nb_or': url.count('|'),
        'nb_eq': url.count('='),
        'nb_underscore': url.count('_'),
        'nb_tilde': url.count('~'),
        'nb_percent': url.count('%'),
        'nb_slash': url.count('/'),
        'nb_star': url.count('*'),
        'nb_colon': url.count(':'),
        'nb_comma': url.count(','),
        'nb_semicolumn': url.count(';'),
        'nb_dollar': url.count('$'),
        'nb_space': url.count(' '),
        'nb_www': url.lower().count('www'),
        'nb_com': url.lower().count('.com'),
        'nb_dslash': url.count('//'),
        'http_in_path': int('http' in path.lower()),
        'https_token': int('https' in url.lower() and not url.lower().startswith('https')),
        'ratio_digits_url': sum(c.isdigit() for c in url) / len(url),
        'ratio_digits_host': sum(c.isdigit() for c in host) / len(host) if host else 0,
        'punycode': int('xn--' in url.lower()),
        'port': int(parsed.port is not None),
        'tld_in_path': int(any(t in path.lower() for t in ['.com','.net','.org'])),
        'tld_in_subdomain': int(any(t in host.lower() for t in ['.com','.net','.org']) and host.count('.') > 1),
        'abnormal_subdomain': int(host.count('.') > 3),
        'nb_subdomains': max(0, host.count('.') - 1),
        'prefix_suffix': int('-' in host),
        'random_domain': int(len(re.findall('[0-9]', host)) > len(host)*0.3),
        'shortening_service': int(any(s in url.lower() for s in ['bit.ly','tinyurl','goo.gl','t.co'])),
        'path_extension': int(bool(re.search(r'\.[a-zA-Z0-9]{2,4}$', path))),
        'nb_redirection': max(0, url.count('//') - 1),
        'nb_external_redirection': int('redirect' in url.lower()),
        'length_words_raw': url_wc,
        'char_repeat': char_repeat_score(url),
        'shortest_words_raw': shortest_url,
        'shortest_word_host': shortest_host,
        'shortest_word_path': shortest_path,
        'longest_words_raw': longest_url,
        'longest_word_host': longest_host,
        'longest_word_path': longest_path,
        'avg_words_raw': avg_url,
        'avg_word_host': avg_host,
        'avg_word_path': avg_path,
        'phish_hints': sum(1 for w in phish_words if w in url.lower()),
        'domain_in_brand': int(any(b in host.lower() for b in brands)),
        'brand_in_subdomain': int(any(b in host.lower() for b in brands) and host.count('.') > 1),
        'brand_in_path': int(any(b in path.lower() for b in brands)),
        'suspecious_tld': int(any(t in url.lower() for t in suspicious_tlds)),
        'statistical_report': int(len(url) > 100 or host.count('.') > 4),

        'nb_hyperlinks': 0,
        'ratio_intHyperlinks': 0.5,
        'ratio_extHyperlinks': 0.5,
        'ratio_nullHyperlinks': 0,
        'nb_extCSS': 0,
        'ratio_intRedirection': 0.5,
        'ratio_extRedirection': 0.5,
        'ratio_intErrors': 0,
        'ratio_extErrors': 0,

        'login_form': int('login' in url.lower()),
        'external_favicon': 0,
        'links_in_tags': 0,
        'submit_email': int('email' in url.lower()),
        'ratio_intMedia': 0.5,
        'ratio_extMedia': 0.5,
        'sfh': int('#' in url),
        'iframe': 0,
        'popup_window': 0,
        'safe_anchor': int('#' not in url),
        'onmouseover': 0,
        'right_clic': 0,
        'empty_title': 0,
        'domain_in_title': 0,
        'domain_with_copyright': 0,
        'whois_registered_domain': 1,
        'domain_registration_length': 365,
        'domain_age': 365,
        'web_traffic': int(any(x in url.lower() for x in ['click','verify','login'])),
        'dns_record': 1,
        'google_index': 1,
        'page_rank': 1
    }

    return features
