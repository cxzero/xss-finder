/**
 * 
 */
package com.xss.finder.utils;

import java.util.List;
import java.util.stream.Collectors;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;

/**
 * XSS utilities
 * 
 * @author <a href="mailto:jpperata@gmail.com">Juan Pablo Perata</a>
 */
public class XSSUtils {

	public static boolean evaluateOutputForReflectedXSS(Payload p, String content) {
		return (content.contains(p.getPlainValue()));
	}

	public static Pair<String, List<NameValuePair>> getTaintedPost(String url, NameValuePair param, Payload p,
			List<NameValuePair> originalParams) {
		List<NameValuePair> taintedParams = originalParams.stream().collect(Collectors.toList());
		int index = originalParams.indexOf(param);
		taintedParams.set(index, new BasicNameValuePair(param.getName(), p.getEncodedValue()));

		return Pair.of(url, taintedParams);
	}
}
