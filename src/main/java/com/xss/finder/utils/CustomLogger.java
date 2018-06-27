package com.xss.finder.utils;

import java.util.logging.Level;
import java.util.logging.Logger;

import com.xss.finder.objects.Context;

/**
 * Logger wrapper in order to set verbose on or off while running 
 * 
 * @author <a href="mailto:jpperata@gmail.com">Juan Pablo Perata</a>
 */
public class CustomLogger {

	private static CustomLogger instance;

	private Logger logger;

	private boolean verbose = false;

	private CustomLogger(String className) {
		logger = Logger.getLogger(className);
		verbose = Context.getInstance().getCommandArguments().getVerbose();
	}

	public synchronized static CustomLogger getInstance(String className) {
		if (instance == null) {
			instance = new CustomLogger(className);
		}

		return instance;
	}

	public void severe(String message, Exception... e) {
		if (verbose) {
			logger.log(Level.SEVERE, message, e);
		}
	}

	public void println(String message) {
		if (verbose) {
			System.out.println(message);
		}
	}

	public void info(String message, Exception... e) {
		if (verbose) {
			logger.log(Level.INFO, message, e);
		}
	}
	
	public void warning(String message, Exception... e) {
		if (verbose) {
			logger.log(Level.WARNING, message, e);
		}
	}
}
