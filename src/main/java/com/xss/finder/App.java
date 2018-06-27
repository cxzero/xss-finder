package com.xss.finder;

import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

import com.beust.jcommander.JCommander;
import com.xss.finder.controllers.XSSController;
import com.xss.finder.objects.Context;
import com.xss.finder.objects.Executor;
import com.xss.finder.parameters.Arguments;
import com.xss.finder.utils.HttpMethod;

/**
 * Main class
 * 
 * @author <a href="mailto:jpperata@gmail.com">Juan Pablo Perata</a>
 */
public class App {

	private static Logger logger = Logger.getLogger(App.class.getSimpleName());

	public static void main(String[] argv) {

		JCommander commander = null;

		try {
			Arguments arguments = new Arguments();

			commander = JCommander.newBuilder().addObject(arguments).build();
			commander.parse(argv);

			if (arguments.isHelp()) {
				commander.usage();
				System.exit(0);
			}

			startProcessing(arguments);

		} catch (Exception ex) {
			logger.severe(ex.getMessage());
			commander.usage();

		} finally {
			if (Objects.nonNull(commander)) {
				finishProcessing();
			}
		}
	}

	private static void startProcessing(Arguments arguments) {
		Context.getInstance().init(arguments);
		Executor.getInstance().init(arguments.getThreads());

		int processingId = XSSController.registerAsProcessing(arguments.getUrl(), HttpMethod.GET, null);
		XSSController.searchXSSGet(processingId, arguments.getUrl());
	}

	private static void finishProcessing() {
		Executor.getInstance().shutdown(10, TimeUnit.MINUTES);
	}
}
