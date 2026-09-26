import email
import re

def read_email(email_file):
    with open (email_file,"r") as file:
        email_content=file.read()
        
        return email_content

def parse_email(email_content):
    msg = email.message_from_string(email_content)
    return msg

def analyze_headers(msg):
    headers = {
    "From": msg["From"],
    "To": msg["To"],
    "Subject": msg["Subject"],
    "Reply-To": msg["Reply-To"],
    "Return-Path": msg["Return-Path"],
    "Authentication-Results": msg["Authentication-Results"],
}
    return headers

def analyze_body(msg):
    body=msg.get_payload()
    return body
def calculate_risk(headers,body):
    risk_score=0
    reason=[]
    if "spf=fail" in headers["Authentication-Results"]:
        risk_score+=2
        reason.append("SPF authentication failed")
    if "dkim=fail" in headers["Authentication-Results"]:
         risk_score+=2 
         reason.append("DKIM authentication failed") 
    if "dmarc=fail" in headers["Authentication-Results"]:
         risk_score+=3
         reason.append("DMARC authentication failed")
    if headers["From"] != headers["Reply-To"]:
        risk_score+=3  
        reason.append("Reply-To address differs from sender")
    urgent_words = [
    "urgent",
    "act now",
    "immediately",
    "verify",
    "suspended",
    "password",
    "account",
    "salary"
    ]
    body=body.lower()
    for word in urgent_words:
        if word in body:
            risk_score+=1
            reason.append("urgent word has been detected")
            break    
    return risk_score,reason

def extract_domain(email_address):
    email_address = email.utils.parseaddr(email_address)[1]
    domain = email_address.split("@")
    return domain[1]

def extract_urls(body):
    return re.findall(r"https?://\w+\.com",body)

def score(risk_score):
    if risk_score<=2:
        return "LOW"
    elif risk_score<=5:
        return "MEDIUM"
    else:
        return "HIGH"

def generate_report(score_risk, risk_level, reasons, domain_email, urls, headers):
    report = f"""
========== EMAIL SECURITY REPORT ==========

Risk Score : {score_risk}
Risk Level : {risk_level}

Sender  : {headers['From']}
Domain  : {domain_email}
Subject : {headers['Subject']}
Reply-To: {headers['Reply-To']}

Indicators:
"""

    for reason in reasons:
        report += f"- {reason}\n"

    report += "\nURLs:\n"

    for url in urls:
        report += f"- {url}\n"

    report += f"""
Assessment:
The email has been classified as {risk_level} risk
based on the detected security indicators.
"""

    print(report)
def main():
    email_file="email.txt"
    content=read_email(email_file)
    message=parse_email(content)
    header=analyze_headers(message)
    body_content=analyze_body(message)
    score_risk,reasons=calculate_risk(header,body_content)
    domain_email=extract_domain(header["From"])
    url=extract_urls(body_content)
    print(score_risk)
    print(domain_email)
    print(url)
    risk_level = score(score_risk)
    print(risk_level)
    choice = input("Do you want to generate a report? (yes/no): ")
    if choice == "yes":
        generate_report(score_risk, risk_level, reasons, domain_email, url,header)
    
if __name__ == "__main__":
    main()