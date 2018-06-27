package com.xss.finder.utils;

import java.util.Collection;
import java.util.Objects;

/**
 * Generic utilities
 * 
 * @author <a href="mailto:jpperata@gmail.com">Juan Pablo Perata</a>
 */
public class Utils {

	public static boolean isEmpty(String s) {
		return s == null || s.trim().isEmpty();
	}

	public static boolean isNonEmpty(String s) {
		return !isEmpty(s);
	}

	public static <E> boolean isEmpty(Collection<E> c) {
		return (Objects.isNull(c) || c.isEmpty());
	}

	public static <E> boolean isEmpty(E[] c) {
		return (Objects.isNull(c) || c.length == 0);
	}

	public static String simpleWhitespaceEncoding(String s) {
		return s.replace(" ", "%20");
	}
}
