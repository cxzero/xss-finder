/**
 * 
 */
package com.xss.finder.utils;

import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

/**
 * Defines methods for parsing HTML content in order to lookup for links
 * 
 * @author <a href="mailto:jpperata@gmail.com">Juan Pablo Perata</a>
 */
public class HtmlParser {

	public static Pair<List<String>, List<Pair<String, List<NameValuePair>>>> parse(String content, String baseUrl)
			throws MalformedURLException {
		Document doc = Jsoup.parse(content, baseUrl);

		List<String> urlsGET = new ArrayList<>();
		List<Pair<String, List<NameValuePair>>> urlsPOST = new ArrayList<>();

		Elements links = doc.select("a[href]");
		Elements imports = doc.select("link[href]");
		Elements media = doc.select("[src]");
		Elements forms = doc.select("form");

		links.forEach(new Consumer<Element>() {
			@Override
			public void accept(Element l) {
				String u = l.attr("abs:href");
				if (HttpUtils.sameDomain(u, baseUrl)) {
					urlsGET.add(u);
				}
			}
		});

		imports.forEach(new Consumer<Element>() {
			@Override
			public void accept(Element i) {
				String u = i.attr("abs:href");
				if (HttpUtils.sameDomain(u, baseUrl)) {
					urlsGET.add(u);
				}
			}
		});

		media.forEach(new Consumer<Element>() {
			@Override
			public void accept(Element m) {
				String u = m.attr("abs:src");
				if (HttpUtils.sameDomain(u, baseUrl)) {
					urlsGET.add(u);
				}
			}
		});

		forms.forEach(new Consumer<Element>() {
			@Override
			public void accept(Element form) {
				String actionUrl = form.attr("abs:action");
				if (HttpUtils.sameDomain(actionUrl, baseUrl)) {
					Elements inputs = form.getElementsByTag("input");
					List<NameValuePair> params = inputs.stream()
							.map(i -> new BasicNameValuePair(i.attr("name"), i.attr("value")))
							.collect(Collectors.toList());

					String method = form.attr("method");
					if (method.equalsIgnoreCase(HttpMethod.GET.name())) {
						urlsGET.add(Utils.isEmpty(params) ? actionUrl
								: String.format("%s?%s", actionUrl, HttpUtils.stringify(params)));
					} else if (method.equalsIgnoreCase(HttpMethod.POST.name())) {
						urlsPOST.add(Pair.of(actionUrl, Utils.isEmpty(params) ? new ArrayList<>() : params));
					}
				}
			}
		});

		return Pair.of(urlsGET, urlsPOST);
	}
}
