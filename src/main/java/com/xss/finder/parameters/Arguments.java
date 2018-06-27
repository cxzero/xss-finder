package com.xss.finder.parameters;

import com.beust.jcommander.Parameter;

/**
 * Defines the command line parameter mappings
 * 
 * @author <a href="mailto:jpperata@gmail.com">Juan Pablo Perata</a>
 */
public class Arguments {
	@Parameter(names = { "--threads", "-t" }, description = "Maximum number of threads")
	private Integer threads = 1;

	@Parameter(names = { "--url", "-u" }, description = "Url to scan for XSS vulnerabilities", required = true)
	private String url;

	@Parameter(names = { "--cookies", "-c" }, description = "Specify any useful cookie")
	private String cookies;

	@Parameter(names = { "--verbose", "-v" }, description = "Display verbosity")
	private boolean verbose = false;

	@Parameter(names = { "--help", "-h" }, help = true, description = "Display usage information")
	private boolean help;

	@Parameter(names = { "--output", "-o" }, description = "Output directory of sqlite database named 'xss-finder.db'")
	private String output = "./";

	public Integer getThreads() {
		return threads;
	}

	public String getUrl() {
		return url;
	}

	public String getCookies() {
		return cookies;
	}

	public boolean getVerbose() {
		return verbose;
	}

	public boolean isHelp() {
		return help;
	}

	public String getOutput() {
		return output;
	}
}
