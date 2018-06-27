package com.xss.finder.objects;

import java.io.InputStream;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.text.MessageFormat;
import java.util.Objects;
import java.util.Scanner;
import java.util.logging.Logger;

import com.xss.finder.parameters.ExecutionStatus;
import com.xss.finder.parameters.ProcessingURLStatus;
import com.xss.finder.utils.HttpMethod;
import com.xss.finder.utils.Payload;
import com.xss.finder.utils.Utils;

/**
 * Wrapper to communicate with sqlite database
 * 
 * @author <a href="mailto:jpperata@gmail.com">Juan Pablo Perata</a>
 */
public class SqliteManager {

	private static Logger logger = Logger.getLogger(SqliteManager.class.getSimpleName());

	private static final String defaultDatabaseURL = "jdbc:sqlite:{0}xss-finder.db";

	private static final String ddlFile = "sql/sqlite.dll.sql";

	private static SqliteManager instance = new SqliteManager();

	SqliteManager() {
	}

	public synchronized static SqliteManager getInstance() {
		return instance;
	}

	public Connection getConnection() throws SQLException {
		String db = MessageFormat.format(defaultDatabaseURL, Context.getInstance().getCommandArguments().getOutput());

		return DriverManager.getConnection(db);
	}

	public void createOrGetExistingDatabase() {
		InputStream ddlResource = Thread.currentThread().getContextClassLoader().getResourceAsStream(ddlFile);
		if (ddlResource == null) {
			throw new IllegalStateException("Initial database ddl file not propertly loaded.");
		}

		final Scanner scanner = new Scanner(ddlResource);
		scanner.useDelimiter("!!");

		Connection connection = null;
		Statement statement = null;

		try {
			connection = getConnection();
			statement = connection.createStatement();

			while (scanner.hasNext()) {
				String ddlEntry = scanner.next();
				if (Utils.isNonEmpty(ddlEntry)) {
					statement.addBatch(ddlEntry.trim());
				}
			}

			statement.executeBatch();

		} catch (Exception e) {
			logger.severe(e.getMessage());
		} finally {
			scanner.close();
			close(connection, statement, null);

			try {
				if (ddlResource != null) {
					ddlResource.close();
				}
			} catch (final Exception e) {
				logger.warning("Failed to close ddl resource");
			}
		}
	}

	private void close(final Connection conn, final Statement stmt, final ResultSet rs) {
		if (Objects.nonNull(rs)) {
			try {
				rs.close();
			} catch (final SQLException e) {
				logger.warning("Failed to close result set");
			}
		}

		if (Objects.nonNull(stmt)) {
			try {
				stmt.close();
			} catch (final SQLException e) {
				logger.warning("Failed to close statement");
			}
		}

		if (Objects.nonNull(conn)) {
			try {
				conn.close();
			} catch (final SQLException e) {
				logger.warning("Failed to close connection");
			}
		}
	}

	public int insertNewExecution() {
		Connection connection = null;
		PreparedStatement statement = null;

		try {
			connection = getConnection();
			statement = connection.prepareStatement("INSERT INTO EXECUTION (START_TIME, STATUS) VALUES (?,?)");

			Timestamp timestamp = new Timestamp(System.currentTimeMillis());
			statement.setTimestamp(1, timestamp);
			statement.setString(2, ExecutionStatus.STARTED.name());
			statement.executeUpdate();

			return getLastInsertRowId("EXECUTION");

		} catch (Exception e) {
			logger.severe(e.getMessage());
			throw new RuntimeException("Unable to insert new execution");
		} finally {
			close(connection, statement, null);
		}
	}

	public int updateExecution(int executionId, ExecutionStatus status) {
		Connection connection = null;
		PreparedStatement statement = null;

		try {
			connection = getConnection();
			statement = connection
					.prepareStatement("UPDATE EXECUTION SET END_TIME = ?, STATUS = ? WHERE EXECUTION_ID = ?");

			Timestamp timestamp = new Timestamp(System.currentTimeMillis());
			statement.setTimestamp(1, timestamp);
			statement.setString(2, status.name());
			statement.setInt(3, executionId);

			return statement.executeUpdate();

		} catch (Exception e) {
			logger.severe(e.getMessage());
			throw new RuntimeException("Unable to update execution");
		} finally {
			close(connection, statement, null);
		}
	}

	public synchronized int insertNewProcessingUrl(String url, HttpMethod method) {
		Connection connection = null;
		PreparedStatement statement = null;

		try {
			connection = getConnection();
			statement = connection.prepareStatement(
					"INSERT INTO PROCESSING_URL (EXECUTION_ID, URL, HTTP_METHOD, STATUS, VULNERABLE) VALUES (?,?,?,?,?)");

			statement.setInt(1, Executor.getInstance().getExecutionId());
			statement.setString(2, url);
			statement.setString(3, method.name());
			statement.setString(4, ProcessingURLStatus.STARTED.name());
			statement.setBoolean(5, false);
			statement.executeUpdate();

			return getLastInsertRowId("PROCESSING_URL");

		} catch (Exception e) {
			logger.severe(e.getMessage());
			throw new RuntimeException("Unable to insert new exection");
		} finally {
			close(connection, statement, null);
		}
	}

	public synchronized int updateProcessingUrl(int processingId, boolean seemsVulnerable, ProcessingURLStatus status) {
		Connection connection = null;
		PreparedStatement statement = null;

		try {
			connection = getConnection();
			statement = connection.prepareStatement(
					"UPDATE PROCESSING_URL SET STATUS = ?, VULNERABLE = ? WHERE PROCESSING_URL_ID = ?");

			statement.setString(1, status.name());
			statement.setBoolean(2, seemsVulnerable);
			statement.setInt(3, processingId);
			return statement.executeUpdate();

		} catch (Exception e) {
			logger.severe(e.getMessage());
			throw new RuntimeException("Unable to insert new exection");
		} finally {
			close(connection, statement, null);
		}
	}

	public synchronized int insertNewTaintedParameter(int processingId, String parameterName, boolean isInjectable,
			Payload p) {
		Connection connection = null;
		PreparedStatement statement = null;

		try {
			connection = getConnection();
			statement = connection.prepareStatement(
					"INSERT INTO TAINTED_PARAMETER (PROCESSING_URL_ID, PARAMETER_NAME, IS_INJECTABLE, PAYLOAD) VALUES (?,?,?,?)");

			statement.setInt(1, processingId);
			statement.setString(2, parameterName);
			statement.setBoolean(3, isInjectable);
			statement.setString(4, p.getPlainValue());
			statement.executeUpdate();

			return getLastInsertRowId("TAINTED_PARAMETER");

		} catch (Exception e) {
			logger.severe(e.getMessage());
			throw new RuntimeException("Unable to insert new tainted parameter");
		} finally {
			close(connection, statement, null);
		}
	}

	public int getLastInsertRowId(String tableName) {
		Connection connection = null;
		PreparedStatement statement = null;
		ResultSet rs = null;

		try {
			connection = getConnection();
			statement = connection.prepareStatement("SELECT SEQ FROM sqlite_sequence WHERE name = ?");
			statement.setString(1, tableName);
			rs = statement.executeQuery();

			return rs.getInt("SEQ");

		} catch (Exception e) {
			logger.severe(e.getMessage());
			throw new RuntimeException("Unable to get last sequence number");
		} finally {
			close(connection, statement, rs);
		}
	}
}
