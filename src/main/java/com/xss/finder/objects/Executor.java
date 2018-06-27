package com.xss.finder.objects;

import java.text.MessageFormat;
import java.util.Queue;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

import com.xss.finder.parameters.ExecutionStatus;

/**
 * Designed to be the wrapper API to communicate with the Executor Service.
 * Provides methods to initialize and finish the executor and also submit tasks
 * to be executed by the pool of threads.
 * 
 * @author <a href="mailto:jpperata@gmail.com">Juan Pablo Perata</a>
 */
public class Executor {

	Logger logger = Logger.getLogger(Executor.class.getSimpleName());

	private static Executor instance = new Executor();

	Queue<Future<?>> futures = new ConcurrentLinkedQueue<Future<?>>();

	ExecutorService executorService;

	int executionId;

	private Executor() {

	}

	public int getExecutionId() {
		return executionId;
	}

	public void clear() {
		instance = new Executor();
	}

	public synchronized static Executor getInstance() {
		return instance;
	}

	private void setMaxConcurrentThreads(int nThreads) {
		if (executorService != null) {
			throw new IllegalStateException("Number of threads cannot be set more than once.");
		}

		executorService = Executors.newFixedThreadPool(nThreads);
	}

	public synchronized void init(int nThreads) {
		setMaxConcurrentThreads(nThreads);

		executionId = SqliteManager.getInstance().insertNewExecution();
		logger.info(MessageFormat.format("Running execution {0}...", executionId));
	}

	private void markExecutionAsComplete() {
		SqliteManager.getInstance().updateExecution(executionId, ExecutionStatus.COMPLETED);
	}

	public synchronized <T> void submit(Callable<T> task) {
		if (executorService == null) {
			throw new IllegalStateException("Executor Service not initialized.");
		}

		Future<?> f = executorService.submit(task);
		futures.add(f);
	}

	public synchronized void submit(Runnable task) {
		if (executorService == null) {
			throw new IllegalStateException("Executor Service not initialized.");
		}

		Future<?> f = executorService.submit(task);
		futures.add(f);
	}

	public void shutdown(long timeout, TimeUnit unit) {
		if (executorService == null) {
			return;
		}

		// A) Await all runnables to be done (blocking)
		for (Future<?> future : futures) {
			try {
				TimeUnit.SECONDS.sleep(1);
				future.get(); // get will block until the future is done
			} catch (InterruptedException | ExecutionException e) {
				logger.severe(MessageFormat.format("Could not get future task data. Detail: {0}", e.getMessage()));
			}
		}

		// B) Check if all runnables are done (non-blocking)
		boolean allDone = true;
		for (Future<?> future : futures) {
			allDone &= future.isDone(); // check if future is done
		}

		logger.info(MessageFormat.format("All tasks done? {0}", allDone));

		try {
			logger.info("Attempt to shutdown executor ...");
			logger.info(MessageFormat.format("Awaiting for termination in {0} {1}...", timeout, unit.toString()));

			executorService.shutdown();
			executorService.awaitTermination(timeout, unit);
		} catch (InterruptedException e) {
			logger.severe("Tasks interrupted.");
		} finally {

			if (!executorService.isTerminated()) {
				logger.warning("Cancel non-finished tasks.");
			}

			markExecutionAsComplete();
			executorService.shutdownNow();
			logger.info("Shutdown complete.");
		}
	}
}
