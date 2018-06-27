package com.xss.finder.utils;

import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;

/**
 * Provides fuzzing capabilities
 * 
 * @author <a href="mailto:jpperata@gmail.com">Juan Pablo Perata</a>
 */
public class Fuzzer {

	private static final String FLAG = "__FUZZ__";

	/*
	 * Returns a map with {key, value} = {parameter name, url with optional flag
	 * FLAG}
	 */
	public static Map<String, String> identifyFuzzableVariations(String url) throws URISyntaxException {
		Map<String, String> variations = new HashMap<>();

		Pair<String, List<NameValuePair>> p = HttpUtils.parseURL(url);
		String urlPrefix = p.getLeft();
		List<NameValuePair> params = p.getRight();

		if (params != null && params.size() > 0) {
			for (NameValuePair param : params) {
				// clone param list, replace param with flag
				List<NameValuePair> cloneParams = params.stream().collect(Collectors.toList());
				int index = params.indexOf(param);
				cloneParams.set(index, new BasicNameValuePair(param.getName(), FLAG));

				variations.put(param.getName(),
						new StringBuffer(urlPrefix).append("?").append(HttpUtils.stringify(cloneParams)).toString());
			}
		} else {
			// No query string parameters found. Add the uri "AS IS".
			variations.put("", url);
		}

		return variations;
	}

	/*
	 * Performs URI fuzzing based on a list of XSS payloads defines in Payloads.java
	 */
	public static List<Pair<String, Payload>> performFuzzing(String fuzzURI) throws URISyntaxException {
		List<Pair<String, Payload>> result = new ArrayList<>();

		if (fuzzURI.toString().contains(FLAG)) {
			for (Payload p : Payload.values()) {
				result.add(Pair.of(replaceFuzzableParameter(fuzzURI, p), p));
			}
		}

		return result;
	}

	public static String replaceFuzzableParameter(String fuzzURI, Payload p) throws URISyntaxException {
		String pContent = p.getEncodedValue();
		String url = fuzzURI.replace(FLAG, pContent);
		return url;
	}
}
