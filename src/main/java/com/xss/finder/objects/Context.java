package com.xss.finder.objects;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import org.apache.commons.lang3.tuple.Triple;
import org.apache.http.NameValuePair;

import com.xss.finder.parameters.Arguments;
import com.xss.finder.parameters.ProcessingURLStatus;
import com.xss.finder.utils.HttpMethod;
import com.xss.finder.utils.Payload;
import com.xss.finder.utils.UrlUtils;

/**
 * Designed for keeping the context of the current execution
 * 
 * @author <a href="mailto:jpperata@gmail.com">Juan Pablo Perata</a>
 */
public class Context {

	private static Context instance = new Context();

	private Arguments commandArguments;

	/**
	 * A list of triplets {url, method, post_parameter_names} in order to keep
	 * current processing urls
	 */
	List<Triple<String, HttpMethod, String>> processingURLs = new ArrayList<>();

	ReadWriteLock processingLock = new ReentrantReadWriteLock();

	ReadWriteLock vulnerableLock = new ReentrantReadWriteLock();

	public synchronized static Context getInstance() {
		return instance;
	}

	private Context() {

	}

	public void clear() {
		instance = new Context();
	}

	public void init(Arguments arguments) {
		setCommandArguments(arguments);
		SqliteManager.getInstance().createOrGetExistingDatabase();
	}

	private void setCommandArguments(Arguments arguments) {
		commandArguments = arguments;
	}

	public Arguments getCommandArguments() {
		return commandArguments;
	}

	public boolean existProcessingURL(String url, HttpMethod method, List<NameValuePair> postParams) {
		processingLock.readLock().lock();
		try {
			return processingURLs.contains(Triple.of(UrlUtils.canonicalizeURL(url), method,
					method.equals(HttpMethod.GET) ? "" : UrlUtils.canonicalizeParams(postParams)));
		} finally {
			processingLock.readLock().unlock();
		}
	}

	public int storeProcessingURL(String url, HttpMethod method, List<NameValuePair> postParams) {
		processingLock.writeLock().lock();
		try {
			processingURLs.add(Triple.of(UrlUtils.canonicalizeURL(url), method,
					method.equals(HttpMethod.GET) ? "" : UrlUtils.canonicalizeParams(postParams)));

			int processingId = SqliteManager.getInstance().insertNewProcessingUrl(UrlUtils.canonicalizeURL(url),
					method);
			return processingId;

		} finally {
			processingLock.writeLock().unlock();
		}
	}

	public void markProcessingURLAsComplete(int processingId, boolean seemsVulnerable) {
		SqliteManager.getInstance().updateProcessingUrl(processingId, seemsVulnerable, ProcessingURLStatus.COMPLETED);
	}

	public void storeTaintedParameter(int processingId, String parameterName, boolean isInjectable, Payload p) {
		SqliteManager.getInstance().insertNewTaintedParameter(processingId, parameterName, isInjectable, p);
	}
}
