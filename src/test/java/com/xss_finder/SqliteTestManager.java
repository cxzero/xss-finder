package com.xss_finder;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Objects;
import java.util.logging.Logger;

/**
 * Wrapper to communicate with sqlite database
 * 
 * @author <a href="mailto:jpperata@gmail.com">Juan Pablo Perata</a>
 */
public class SqliteTestManager {

	private static Logger logger = Logger.getLogger(SqliteTestManager.class.getSimpleName());

	private static final String defaultDatabaseURL = "jdbc:sqlite:xss-finder.db";

	private static SqliteTestManager instance = new SqliteTestManager();

	SqliteTestManager() {
	}

	public synchronized static SqliteTestManager getInstance() {
		return instance;
	}

	public Connection getConnection() throws SQLException {
		return DriverManager.getConnection(defaultDatabaseURL);
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

	public int getVulnerableURLsCount(int executionId) {
		Connection connection = null;
		PreparedStatement statement = null;

		try {
			connection = getConnection();
			statement = connection
					.prepareStatement("SELECT COUNT(*) AS COUNTER FROM PROCESSING_URL WHERE EXECUTION_ID = ? AND VULNERABLE");

			statement.setInt(1, executionId);
			ResultSet rs = statement.executeQuery();

			return rs.getInt("COUNTER");

		} catch (Exception e) {
			logger.severe(e.getMessage());
			throw new RuntimeException("Unable to insert new tainted parameter");
		} finally {
			close(connection, statement, null);
		}
	}

}
