package com.xss.finder.controllers;

import java.net.URISyntaxException;
import java.text.MessageFormat;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.function.Consumer;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.http.NameValuePair;

import com.xss.finder.objects.Context;
import com.xss.finder.objects.Executor;
import com.xss.finder.utils.CustomLogger;
import com.xss.finder.utils.Fuzzer;
import com.xss.finder.utils.HtmlParser;
import com.xss.finder.utils.HttpMethod;
import com.xss.finder.utils.HttpUtils;
import com.xss.finder.utils.Payload;
import com.xss.finder.utils.Utils;
import com.xss.finder.utils.XSSUtils;

/**
 * Defines core functionality to search for XSS vulnerabilities based on an initial URL
 * 
 * @author <a href="mailto:jpperata@gmail.com">Juan Pablo Perata</a>
 */
public class XSSController {

	private static CustomLogger logger = CustomLogger.getInstance(XSSController.class.getSimpleName());

	private static void submitXssSearchTask(String url, HttpMethod method, List<NameValuePair> postParams,
			int processingId) {
		Runnable task = () -> {
			String threadName = Thread.currentThread().getName();
			logger.println(MessageFormat.format("Thread {0}, about to process {1}", threadName, url));

			if (method.equals(HttpMethod.GET)) {
				searchXSSGet(processingId, url);
			} else {
				searchXSSPost(processingId, url, postParams);
			}
		};

		Executor.getInstance().submit(task);
	}

	public static void searchXSSGet(int processingId, String url) {
		try {
			boolean seemsVulnerable = false;

			Map<String, String> fuzzableURIs = Fuzzer.identifyFuzzableVariations(url);
			for (Entry<String, String> entry : fuzzableURIs.entrySet()) {
				String parameterName = entry.getKey();
				String u = entry.getValue();

				List<Pair<String, Payload>> taintedURIs = Fuzzer.performFuzzing(u);

				if (Utils.isEmpty(taintedURIs)) {
					xssCheck(u);
				} else {
					for (Pair<String, Payload> t : taintedURIs) {
						String content = xssCheck(t.getLeft());
						boolean isInjectableParameter = XSSUtils.evaluateOutputForReflectedXSS(t.getRight(), content);
						seemsVulnerable |= isInjectableParameter;

						Context.getInstance().storeTaintedParameter(processingId, parameterName, isInjectableParameter,
								t.getRight());
						logger.println(MessageFormat.format(
								"({3}) Tainted url: {0}, Payload: {1}, Seems vulnerable: {2}", t.getLeft(),
								t.getRight().getPlainValue(), isInjectableParameter, Thread.currentThread().getName()));
					}
				}
			}

			Context.getInstance().markProcessingURLAsComplete(processingId, seemsVulnerable);

		} catch (URISyntaxException e) {
			logger.severe("Syntax error", e);
		}
	}

	public static String xssCheck(String url) {
		String content = HttpUtils.performGet(url);
		processContent(content, url);
		return content;
	}

	public static void searchXSSPost(int processingId, String url, List<NameValuePair> originalParams) {
		boolean seemsVulnerable = false;

		for (NameValuePair param : originalParams) {
			for (Payload p : Payload.values()) {
				Pair<String, List<NameValuePair>> taintedPost = XSSUtils.getTaintedPost(url, param, p, originalParams);
				boolean isInjectableParameter = xssCheckPost(taintedPost.getLeft(), taintedPost.getRight(), p);
				seemsVulnerable |= isInjectableParameter;

				Context.getInstance().storeTaintedParameter(processingId, param.getName(), isInjectableParameter, p);

				logger.println(MessageFormat.format(
						"({4}) Tainted url: {0}, Payload: {1}, Seems vulnerable: {2}, Parameter {3}, Method: POST", url,
						p.getPlainValue(), isInjectableParameter, param.getName(), Thread.currentThread().getName()));
			}
		}

		Context.getInstance().markProcessingURLAsComplete(processingId, seemsVulnerable);
	}

	public static boolean xssCheckPost(String url, List<NameValuePair> params, Payload p) {
		String content = HttpUtils.performPost(url, HttpUtils.stringify(params));
		processContent(content, url);
		return (content.contains(p.getPlainValue()));
	}

	/*
	 * Perform a recursive XSS search over all links in HTML content
	 */
	public static void processContent(String content, String url) {
		try {
			Pair<List<String>, List<Pair<String, List<NameValuePair>>>> links = HtmlParser.parse(content, url);

			// Process GET's
			links.getLeft().forEach(new Consumer<String>() {
				@Override
				public void accept(String u) {
					if (alreadyNotProcessed(u, HttpMethod.GET, null)) {
						int processingId = registerAsProcessing(u, HttpMethod.GET, null);
						submitXssSearchTask(u, HttpMethod.GET, null, processingId);
					}
				}
			});

			// Process POST's
			links.getRight().forEach(new Consumer<Pair<String, List<NameValuePair>>>() {
				@Override
				public void accept(Pair<String, List<NameValuePair>> p) {
					if (alreadyNotProcessed(p.getLeft(), HttpMethod.POST, p.getRight())) {
						int processingId = registerAsProcessing(p.getLeft(), HttpMethod.POST, p.getRight());
						submitXssSearchTask(p.getLeft(), HttpMethod.POST, p.getRight(), processingId);
					}
				}
			});

		} catch (Exception e) {
			logger.severe("Error while processing content", e);
		}
	}

	private static boolean alreadyNotProcessed(String url, HttpMethod method, List<NameValuePair> params) {
		return !Context.getInstance().existProcessingURL(url, method, params);
	}

	public static int registerAsProcessing(String url, HttpMethod method, List<NameValuePair> params) {
		logger.info(MessageFormat.format("Registering url to be processed {0}, {1}", url, method.toString()));
		int processingId = Context.getInstance().storeProcessingURL(url, method, params);

		return processingId;
	}
}
