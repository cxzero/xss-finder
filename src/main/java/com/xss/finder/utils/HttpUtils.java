package com.xss.finder.utils;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;

import com.xss.finder.objects.Context;

/**
 * Http utilities
 * 
 * @author <a href="mailto:jpperata@gmail.com">Juan Pablo Perata</a>
 */
public class HttpUtils {

	private static Logger logger = Logger.getLogger(HttpUtils.class.getSimpleName());

	private static final String USER_AGENT = "XSS Tester Java client";

	public static String performGet(String urlToRead) {

		StringBuffer content = new StringBuffer();
		URL url;
		HttpURLConnection conn = null;

		try {
			url = new URL(urlToRead);
			conn = (HttpURLConnection) url.openConnection();
			conn.setRequestMethod(HttpMethod.GET.name());

			String cookies = Context.getInstance().getCommandArguments().getCookies();
			if (Utils.isNonEmpty(cookies)) {
				conn.setRequestProperty("Cookie", cookies);
			}

			conn.setRequestProperty("User-Agent", USER_AGENT);
			conn.setRequestProperty("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
			conn.setRequestProperty("Accept-Language", "en-US,en;q=0.5");
			conn.setConnectTimeout(15000);
			conn.setReadTimeout(15000);

			try (BufferedReader rd = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
				String line = "";

				while ((line = rd.readLine()) != null) {
					content.append(line);
					content.append(System.lineSeparator());
				}
			}

		} catch (FileNotFoundException e) {
			// resource not found, do nothing
		} catch (IOException e) {
			logger.log(Level.SEVERE, "Unable to get read content line", e.getMessage());

		} finally {
			conn.disconnect();
		}

		return content.toString();
	}

	/**
	 * 
	 * @param urlToRead
	 * @param data
	 *            POST data in format "param1=val1&param2=val2&param3=val3 ..."
	 */
	public static String performPost(String urlToRead, String data) {

		Pattern p = Pattern.compile("(\\w+=.*)(&(\\w+=.*))*");
		if (!p.matcher(data).matches()) {
			throw new IllegalArgumentException("Unrecognized POST data format");
		}

		StringBuffer content = new StringBuffer();
		URL url;
		HttpURLConnection conn = null;

		try {
			url = new URL(urlToRead);
			conn = (HttpURLConnection) url.openConnection();
			conn.setRequestMethod(HttpMethod.POST.name());
			conn.setDoOutput(true);
			conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
			conn.setRequestProperty("Content-Length", String.valueOf(data.length()));

			String cookies = Context.getInstance().getCommandArguments().getCookies();
			if (Utils.isNonEmpty(cookies)) {
				conn.setRequestProperty("Cookie", cookies);
			}

			conn.setRequestProperty("User-Agent", USER_AGENT);
			conn.setConnectTimeout(15000);
			conn.setReadTimeout(15000);

			try (DataOutputStream wr = new DataOutputStream(conn.getOutputStream())) {
				wr.write(data.getBytes());
			}

			try (BufferedReader rd = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
				String line = "";

				while ((line = rd.readLine()) != null) {
					content.append(line);
					content.append(System.lineSeparator());
				}
			}
		} catch (IOException e) {
			logger.log(Level.SEVERE, "Unable to get read content line", e.getMessage());

		} finally {
			conn.disconnect();
		}

		return content.toString();
	}

	public static String stringify(List<NameValuePair> params) {
		String res = params.stream().map(p -> String.format("%s=%s", p.getName(), p.getValue()))
				.collect(Collectors.joining("&"));
		return Utils.simpleWhitespaceEncoding(res);
	}

	public static boolean sameDomain(String url1, String url2) {
		try {
			if (StringUtils.isBlank(url1) || StringUtils.isBlank(url2)) {
				return false;
			}

			return (new URL(url1).getHost().equalsIgnoreCase(new URL(url2).getHost()));

		} catch (MalformedURLException e) {
			logger.log(Level.WARNING, "Error while checking url same domain" + url1 + "/" + url2, e.getMessage());
			return false;
		}
	}

	public static Pair<String, List<NameValuePair>> parseURL(String url) {
		Pattern p = Pattern.compile("((\\w+=.*)(&(\\w+=.*))*)");
		Matcher m = p.matcher(url);
		String data = "";
		String urlPrefix = "";
		if (m.find()) {
			data = m.group(1);
			urlPrefix = url.substring(0, m.start() - 1); // To avoid last character '?'
		} else {
			urlPrefix = url;
		}

		List<NameValuePair> params = URLEncodedUtils.parse(data, StandardCharsets.UTF_8, '&');

		return Pair.of(urlPrefix, params);
	}
}
