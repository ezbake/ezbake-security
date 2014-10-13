package ezbake.security.client.validation;

import ezbake.base.thrift.EzSecurityTokenException;
import ezbake.security.common.core.TokenExpiredException;
import org.apache.thrift.TBase;

/**
 * User: jhastings
 * Date: 10/13/14
 * Time: 10:32 AM
 */
public interface TokenValidator<T extends TBase> {
    public void validateToken(T token) throws EzSecurityTokenException, TokenExpiredException;
}
