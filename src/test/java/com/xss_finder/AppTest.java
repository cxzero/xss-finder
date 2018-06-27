package com.xss_finder;

import java.util.logging.Logger;

import com.xss.finder.App;
import com.xss.finder.objects.Context;
import com.xss.finder.objects.Executor;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * Unit tests for App.
 *
 * @author <a href="mailto:jpperata@gmail.com">Juan Pablo Perata</a>
 */
public class AppTest extends TestCase {

	Logger logger = Logger.getLogger(AppTest.class.getSimpleName());

	/**
	 * Create the test case
	 */
	public AppTest(String testName) {
		super(testName);
	}

	private void init() {
		Context.getInstance().clear();
		Executor.getInstance().clear();
	}

	/**
	 * @return the suite of tests being tested
	 */
	public static Test suite() {
		return new TestSuite(AppTest.class);
	}

	public void testXSSGruyereWithoutCookies() {
		logger.info("Simple testing gruyere without cookies.");

		init();

		App.main(new String[] { "--url", "https://google-gruyere.appspot.com/644852684643130374734504617997246469911/",
				"--threads", "5" });

		int executionId = Executor.getInstance().getExecutionId();
		int vulnerableURLs = SqliteTestManager.getInstance().getVulnerableURLsCount(executionId);

		assertTrue(vulnerableURLs == 1);
	}

	public void testXSSGame() {
		logger.info("Simple testing XSS game.");

		init();

		App.main(new String[] { "--url", "https://xss-game.appspot.com", "--threads", "2" });

		int executionId = Executor.getInstance().getExecutionId();
		int vulnerableURLs = SqliteTestManager.getInstance().getVulnerableURLsCount(executionId);

		assertTrue(vulnerableURLs == 1);
	}

	public void testXSSGruyereWithCookies() {
		logger.info("Simple testing gruyere with cookies.");

		init();

		App.main(new String[] { "--url", "https://google-gruyere.appspot.com/644852684643130374734504617997246469911/",
				"--threads", "4", "--cookies", "GRUYERE=937276|a||author" });

		int executionId = Executor.getInstance().getExecutionId();
		int vulnerableURLs = SqliteTestManager.getInstance().getVulnerableURLsCount(executionId);

		assertTrue(vulnerableURLs == 3);
	}
}
