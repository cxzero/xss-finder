/**
 * 
 */
package com.xss.finder.utils;

import java.util.List;
import java.util.stream.Collectors;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.http.NameValuePair;

/**
 * Url utilities
 * 
 * @author <a href="mailto:jpperata@gmail.com">Juan Pablo Perata</a>
 */
public class UrlUtils {

	/**
	 * What means canonicalization in this context is to reduce to the minimum
	 * expression the url, in which the query string parameters are reduced to the
	 * form "param_name="
	 * 
	 * Final url is meant to be path?p1=&p2=&p3=&...
	 */
	public static String canonicalizeURL(String url) {
		Pair<String, List<NameValuePair>> parsed = HttpUtils.parseURL(url);

		String canonicParams = canonicalizeParams(parsed.getRight());
		return (canonicParams.isEmpty()) ? parsed.getLeft() : String.format("%s?%s", parsed.getLeft(), canonicParams);

	}

	public static String canonicalizeParams(List<NameValuePair> params) {
		return params.stream().map(p -> String.format("%s=", p.getName())).sorted().collect(Collectors.joining("&"));
	}
}
