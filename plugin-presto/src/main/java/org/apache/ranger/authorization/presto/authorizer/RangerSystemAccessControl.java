/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.ranger.authorization.presto.authorizer;


import com.facebook.presto.spi.security.Identity;
import com.facebook.presto.spi.security.AccessDeniedException;
import com.facebook.presto.spi.security.PrestoPrincipal;
import com.facebook.presto.spi.security.Privilege;
import com.facebook.presto.spi.security.AccessControlContext;
import com.facebook.presto.spi.security.AuthorizedIdentity;
import com.facebook.presto.spi.security.SystemAccessControl;
import com.facebook.presto.spi.security.SelectedRole;


import com.facebook.presto.common.CatalogSchemaName;
import com.facebook.presto.spi.CatalogSchemaTableName;
import com.facebook.presto.spi.SchemaTableName;


import java.security.cert.X509Certificate;
//import java.util.Collections;

//import static java.util.Objects.requireNonNull;

import org.apache.commons.lang.StringUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.ranger.plugin.audit.RangerDefaultAuditHandler;
//import org.apache.ranger.plugin.model.RangerPolicy;
//import org.apache.ranger.plugin.model.RangerServiceDef;
import org.apache.ranger.plugin.policyengine.RangerAccessRequestImpl;
import org.apache.ranger.plugin.policyengine.RangerAccessResourceImpl;
import org.apache.ranger.plugin.policyengine.RangerAccessResult;
import org.apache.ranger.plugin.service.RangerBasePlugin;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URL;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static java.util.Locale.ENGLISH;

public class RangerSystemAccessControl
  implements SystemAccessControl {
  private static Logger LOG = LoggerFactory.getLogger(RangerSystemAccessControl.class);

  final public static String RANGER_CONFIG_KEYTAB = "ranger.keytab";
  final public static String RANGER_CONFIG_PRINCIPAL = "ranger.principal";
  final public static String RANGER_CONFIG_USE_UGI = "ranger.use_ugi";
  final public static String RANGER_CONFIG_HADOOP_CONFIG = "ranger.hadoop_config";
  final public static String RANGER_PRESTO_DEFAULT_HADOOP_CONF = "presto-ranger-site.xml";
  final public static String RANGER_PRESTO_SERVICETYPE = "presto";
  final public static String RANGER_PRESTO_APPID = "presto";

  final private RangerBasePlugin rangerPlugin;

  private boolean useUgi = false;

  public RangerSystemAccessControl(Map<String, String> config) {
    super();

    Configuration hadoopConf = new Configuration();
    if (config.get(RANGER_CONFIG_HADOOP_CONFIG) != null) {
      URL url =  hadoopConf.getResource(config.get(RANGER_CONFIG_HADOOP_CONFIG));
      if (url == null) {
        LOG.warn("Hadoop config " + config.get(RANGER_CONFIG_HADOOP_CONFIG) + " not found");
      } else {
        hadoopConf.addResource(url);
      }
    } else {
      URL url = hadoopConf.getResource(RANGER_PRESTO_DEFAULT_HADOOP_CONF);
      if (LOG.isDebugEnabled()) {
        LOG.debug("Trying to load Hadoop config from " + url + " (can be null)");
      }
      if (url != null) {
        hadoopConf.addResource(url);
      }
    }
    UserGroupInformation.setConfiguration(hadoopConf);

    if (config.get(RANGER_CONFIG_KEYTAB) != null && config.get(RANGER_CONFIG_PRINCIPAL) != null) {
      String keytab = config.get(RANGER_CONFIG_KEYTAB);
      String principal = config.get(RANGER_CONFIG_PRINCIPAL);

      LOG.info("Performing kerberos login with principal " + principal + " and keytab " + keytab);

      try {
        UserGroupInformation.loginUserFromKeytab(principal, keytab);
      } catch (IOException ioe) {
        LOG.error("Kerberos login failed", ioe);
        throw new RuntimeException(ioe);
      }
    }

    if (config.getOrDefault(RANGER_CONFIG_USE_UGI, "false").equalsIgnoreCase("true")) {
      useUgi = true;
    }

    rangerPlugin = new RangerBasePlugin(RANGER_PRESTO_SERVICETYPE, RANGER_PRESTO_APPID);
    rangerPlugin.init();
    rangerPlugin.setResultProcessor(new RangerDefaultAuditHandler());
  }

  /** HELPER FUNCTIONS **/

  private RangerPrestoAccessRequest createAccessRequest(RangerPrestoResource resource, Identity identity, PrestoAccessType accessType) {
    String userName = null;
    Set<String> userGroups = null;
    Map<String,SelectedRole> userRoles = null;
  
    if (useUgi) {
      UserGroupInformation ugi = UserGroupInformation.createRemoteUser(identity.getUser());

      userName = ugi.getShortUserName();
      String[] groups = ugi != null ? ugi.getGroupNames() : null;
  
      if (groups != null && groups.length > 0) {
        userGroups = new HashSet<>(Arrays.asList(groups));
      } 
    } else {
      userName = identity.getUser();
      userRoles = identity.getRoles();
      userGroups = userRoles.keySet();
    }
    
    RangerPrestoAccessRequest request = new RangerPrestoAccessRequest(
      resource,
      userName,
      userGroups,
      accessType
    );
    
    return request;
  } 

  private boolean hasPermission(RangerPrestoResource resource, Identity identity, PrestoAccessType accessType) {
    boolean ret = false;

    RangerPrestoAccessRequest request = createAccessRequest(resource, identity, accessType);
  
    RangerAccessResult result = rangerPlugin.isAccessAllowed(request);

    if (result != null && result.getIsAllowed()) {
      ret = true;
    }

    if (ret) {
        LOG.debug("hasPermission(" + identity.getUser() + "," + accessType + ") -> true");
    } else {
        LOG.debug("hasPermission(" + identity.getUser() + "," + accessType + ") -> false");
    }
  
    return ret;
  }

  private static RangerPrestoResource createSystemPropertyResource(String property) {
    RangerPrestoResource res = new RangerPrestoResource();
    res.setValue(RangerPrestoResource.KEY_SYSTEM_PROPERTY, property);
      
    return res;
  }   

  private static RangerPrestoResource createCatalogSessionResource(String catalogName, String propertyName) {
    RangerPrestoResource res = new RangerPrestoResource();
    res.setValue(RangerPrestoResource.KEY_CATALOG, catalogName);
    res.setValue(RangerPrestoResource.KEY_SESSION_PROPERTY, propertyName);
  
    return res;
  }

  private static RangerPrestoResource createResource(CatalogSchemaName catalogSchemaName) {
    return createResource(catalogSchemaName.getCatalogName(), catalogSchemaName.getSchemaName());
  }

  private static RangerPrestoResource createResource(CatalogSchemaTableName catalogSchemaTableName) {
    return createResource(catalogSchemaTableName.getCatalogName(),
      catalogSchemaTableName.getSchemaTableName().getSchemaName(),
      catalogSchemaTableName.getSchemaTableName().getTableName());
  }

  private static RangerPrestoResource createResource(String catalogName) {
    return new RangerPrestoResource(catalogName, Optional.empty(), Optional.empty());
  }

  private static RangerPrestoResource createResource(String catalogName, String schemaName) {
    return new RangerPrestoResource(catalogName, Optional.of(schemaName), Optional.empty());
  }

  private static RangerPrestoResource createResource(String catalogName, String schemaName, final String tableName) {
    return new RangerPrestoResource(catalogName, Optional.of(schemaName), Optional.of(tableName));
  }

  private static RangerPrestoResource createResource(String catalogName, String schemaName, final String tableName, final Optional<String> column) {
    return new RangerPrestoResource(catalogName, Optional.of(schemaName), Optional.of(tableName), column);
  }

  private static List<RangerPrestoResource> createResource(CatalogSchemaTableName table, Set<String> columns) {
    List<RangerPrestoResource> colRequests = new ArrayList<>();

    if (columns.size() > 0) {
      for (String column : columns) {
        RangerPrestoResource rangerPrestoResource = createResource(table.getCatalogName(),
          table.getSchemaTableName().getSchemaName(),
          table.getSchemaTableName().getTableName(), Optional.of(column));
        colRequests.add(rangerPrestoResource);
      }
    } else {
      colRequests.add(createResource(table.getCatalogName(),
        table.getSchemaTableName().getSchemaName(),
        table.getSchemaTableName().getTableName(), Optional.empty()));
    }
    return colRequests;
  }

    /**
     * Check if the principal is allowed to be the specified user.
     *
     * @throws AccessDeniedException if not allowed
     */
    @Override
    public void checkCanSetUser(Identity identity, AccessControlContext context, Optional<Principal> principal, String userName) {
    }

    @Override
    public AuthorizedIdentity selectAuthorizedIdentity(Identity identity, AccessControlContext context, String userName, List<X509Certificate> certificates)
    {
        return new AuthorizedIdentity(userName, "", true);
    }

    /**
     * Check if the query is unexpectedly modified using the credentials passed in the identity.
     *
     * @throws AccessDeniedException if query is modified.
     */
    @Override
    public void checkQueryIntegrity(Identity identity, AccessControlContext context, String query) {
    }

    /**
     * Check if identity is allowed to set the specified system property.
     *
     * @throws AccessDeniedException if not allowed
     */
    @Override
    public void checkCanSetSystemSessionProperty(Identity identity, AccessControlContext context, String propertyName) {
          LOG.debug("RangerSystemAccessControl.checkCanSetSystemSessionProperty(" + propertyName + ")");
        if (!hasPermission(createSystemPropertyResource(propertyName), identity, PrestoAccessType.ALTER)) {

          AccessDeniedException.denySetSystemSessionProperty(propertyName);
        }
    }

    /**
     * Check if identity is allowed to access the specified catalog
     *
     * @throws com.facebook.presto.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanAccessCatalog(Identity identity, AccessControlContext context, String catalogName)
    {
        LOG.debug("RangerSystemAccessControl.checkCanAccessCatalog(" + catalogName + ")");
        if (!hasPermission(createResource(catalogName), identity, PrestoAccessType.USE)) {
          AccessDeniedException.denyCatalogAccess(catalogName);
        }
    }

    /**
     * Filter the list of catalogs to those visible to the identity.
     */
    @Override
    public Set<String> filterCatalogs(Identity identity, AccessControlContext context, Set<String> catalogs)
    {
        LOG.debug("==> RangerSystemAccessControl.filterCatalogs("+ catalogs + ")");
        Set<String> filteredCatalogs = new HashSet<>(catalogs.size());
        for (String catalog: catalogs) {
          if (hasPermission(createResource(catalog), identity, PrestoAccessType.SELECT)) {
            filteredCatalogs.add(catalog);
          }
        }
        return filteredCatalogs;
    }

    /**
     * Check if identity is allowed to create the specified schema in a catalog.
     *
     * @throws com.facebook.presto.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanCreateSchema(Identity identity, AccessControlContext context, CatalogSchemaName schema)
    {
        LOG.debug("RangerSystemAccessControl.checkCanCreateSchema(" + schema.getCatalogName() + ")");
        if (!hasPermission(createResource(schema.getCatalogName()), identity, PrestoAccessType.CREATE)) {
          AccessDeniedException.denyCreateSchema(schema.getSchemaName());
        }
    }

    /**
     * Check if identity is allowed to drop the specified schema in a catalog.
     *
     * @throws com.facebook.presto.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanDropSchema(Identity identity, AccessControlContext context, CatalogSchemaName schema)
    {
        LOG.debug("RangerSystemAccessControl.checkCanDropSchema(" + schema.getCatalogName() + ", " + schema.getSchemaName() + ")");
        if (!hasPermission(createResource(schema.getCatalogName(), schema.getSchemaName()), identity, PrestoAccessType.DROP)) {
          AccessDeniedException.denyDropSchema(schema.getSchemaName());
        }
    }

    /**
     * Check if identity is allowed to rename the specified schema in a catalog.
     *
     * @throws com.facebook.presto.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanRenameSchema(Identity identity, AccessControlContext context, CatalogSchemaName schema, String newSchemaName)
    {
        LOG.debug("RangerSystemAccessControl.checkCanRenameSchema(" + schema.getCatalogName() + ", " + schema.getSchemaName() + ") denied");
        RangerPrestoResource res = createResource(schema.getCatalogName(), schema.getSchemaName());
        if (!hasPermission(res, identity, PrestoAccessType.ALTER)) {
          AccessDeniedException.denyRenameSchema(schema.getSchemaName(), newSchemaName);
        }
    }

    /**
     * Check if identity is allowed to execute SHOW SCHEMAS in a catalog.
     * <p>
     * NOTE: This method is only present to give users an error message when listing is not allowed.
     * The {@link #filterSchemas} method must filter all results for unauthorized users,
     * since there are multiple ways to list schemas.
     *
     * @throws com.facebook.presto.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanShowSchemas(Identity identity, AccessControlContext context, String catalogName)
    {
        LOG.debug("RangerSystemAccessControl.checkCanShowSchemas(" + catalogName + ")");
        if (!hasPermission(createResource(catalogName), identity, PrestoAccessType.SHOW)) {
          AccessDeniedException.denyShowSchemas(catalogName);
        }
    }

    /**
     * Filter the list of schemas in a catalog to those visible to the identity.
     */
    @Override
    public Set<String> filterSchemas(Identity identity, AccessControlContext context, String catalogName, Set<String> schemaNames)
    {
        LOG.debug("==> RangerSystemAccessControl.filterSchemas(" + catalogName + ")");
        Set<String> filteredSchemaNames = new HashSet<>(schemaNames.size());
        for (String schemaName: schemaNames) {
          if (hasPermission(createResource(catalogName, schemaName), identity, PrestoAccessType.SELECT)) {
            filteredSchemaNames.add(schemaName);
          } 
        }
        return filteredSchemaNames;
    }

    /**
     * Check if identity is allowed to create the specified table in a catalog.
     *
     * @throws com.facebook.presto.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanCreateTable(Identity identity, AccessControlContext context, CatalogSchemaTableName table)
    {
        LOG.debug("RangerSystemAccessControl.checkCanCreateTable(" + table.getCatalogName() + ", " + table.getSchemaTableName().getSchemaName() + ")");
        if (!hasPermission(createResource(table.getCatalogName(), table.getSchemaTableName().getSchemaName()), identity, PrestoAccessType.CREATE)) {
          AccessDeniedException.denyCreateTable(table.getSchemaTableName().getTableName());
        } 
    }

    /**
     * Check if identity is allowed to drop the specified table in a catalog.
     *
     * @throws com.facebook.presto.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanDropTable(Identity identity, AccessControlContext context, CatalogSchemaTableName table)
    {
        LOG.debug("RangerSystemAccessControl.checkCanDropTable(" + table.getSchemaTableName().getTableName() + ")");
        if (!hasPermission(createResource(table), identity, PrestoAccessType.DROP)) {
          AccessDeniedException.denyDropTable(table.getSchemaTableName().getTableName());
        }
    }

    /**
     * Check if identity is allowed to rename the specified table in a catalog.
     *
     * @throws com.facebook.presto.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanRenameTable(Identity identity, AccessControlContext context, CatalogSchemaTableName table, CatalogSchemaTableName newTable)
    {
        LOG.debug("RangerSystemAccessControl.checkCanRenameTable(" + table.getSchemaTableName().getTableName() + ")");
        RangerPrestoResource res = createResource(table);
        if (!hasPermission(res, identity, PrestoAccessType.ALTER)) {
          AccessDeniedException.denyRenameTable(table.getSchemaTableName().getTableName(), newTable.getSchemaTableName().getTableName());
        }
    }

    /**
     * Check if identity is allowed to show metadata of tables by executing SHOW TABLES, SHOW GRANTS etc. in a catalog.
     * <p>
     * NOTE: This method is only present to give users an error message when listing is not allowed.
     * The {@link #filterTables} method must filter all results for unauthorized users,
     * since there are multiple ways to list tables.
     *
     * @throws com.facebook.presto.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanShowTablesMetadata(Identity identity, AccessControlContext context, CatalogSchemaName schema)
    {
        LOG.debug("RangerSystemAccessControl.checkCanShowTablesMetadata(" + schema.getCatalogName() + ", " + schema.getSchemaName() + ")");
        if (schema.getSchemaName().equals("information_schema")) {
            if (!hasPermission(createResource(schema.getCatalogName()), identity, PrestoAccessType.USE)) {
                AccessDeniedException.denyShowTablesMetadata(schema.getSchemaName());
            }
        }
        if (!hasPermission(createResource(schema.getCatalogName(), schema.getSchemaName()), identity, PrestoAccessType.SHOW)) {
          AccessDeniedException.denyShowTablesMetadata(schema.getSchemaName());
        }
    }

    /**
     * Filter the list of tables and views to those visible to the identity.
     */
    @Override
    public Set<SchemaTableName> filterTables(Identity identity, AccessControlContext context, String catalogName, Set<SchemaTableName> tableNames)
    {
        Set<SchemaTableName> filteredTableNames = new HashSet<>(tableNames.size());
        for (SchemaTableName tableName : tableNames) {
          LOG.debug("RangerSystemAccessControl.filterTables(" + catalogName + ", " + tableName.getSchemaName() + ", " + tableName.getTableName() + ")");
          RangerPrestoResource res = createResource(catalogName, tableName.getSchemaName(), tableName.getTableName());
          if (tableName.getSchemaName().equals("information_schema") && hasPermission(createResource(catalogName), identity, PrestoAccessType.USE)) {
            filteredTableNames.add(tableName);
          } else if (hasPermission(res, identity, PrestoAccessType.SELECT)) {
            filteredTableNames.add(tableName);
          }
        }
        return filteredTableNames;
    }

    /**
     * Check if identity is allowed to add columns to the specified table in a catalog.
     *
     * @throws com.facebook.presto.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanAddColumn(Identity identity, AccessControlContext context, CatalogSchemaTableName table)
    {
        LOG.debug("RangerSystemAccessControl.checkCanAddColumn(" + table.getSchemaTableName().getTableName() + ")");
        RangerPrestoResource res = createResource(table);
        if (!hasPermission(res, identity, PrestoAccessType.ALTER)) {
          AccessDeniedException.denyAddColumn(table.getSchemaTableName().getTableName());
        } 
    }

    /**
     * Check if identity is allowed to drop columns from the specified table in a catalog.
     *
     * @throws com.facebook.presto.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanDropColumn(Identity identity, AccessControlContext context, CatalogSchemaTableName table)
    {
        LOG.debug("RangerSystemAccessControl.checkCanDropColumn(" + table.getSchemaTableName().getTableName() + ")");
        RangerPrestoResource res = createResource(table);
        if (!hasPermission(res, identity, PrestoAccessType.DROP)) {

          AccessDeniedException.denyDropColumn(table.getSchemaTableName().getTableName());
        }
    }

    /**
     * Check if identity is allowed to rename a column in the specified table in a catalog.
     *
     * @throws com.facebook.presto.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanRenameColumn(Identity identity, AccessControlContext context, CatalogSchemaTableName table)
    {
        RangerPrestoResource res = createResource(table);
        LOG.debug("RangerSystemAccessControl.checkCanRenameColumn(" + table.getSchemaTableName().getTableName() + ") denied");
        if (!hasPermission(res, identity, PrestoAccessType.ALTER)) {
          AccessDeniedException.denyRenameColumn(table.getSchemaTableName().getTableName());
        }
    }

    /**
     * Check if identity is allowed to select from the specified columns in a relation.  The column set can be empty.
     *
     * @throws com.facebook.presto.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanSelectFromColumns(Identity identity, AccessControlContext context, CatalogSchemaTableName table, Set<String> columns)
    {
        LOG.debug("RangerSystemAccessControl.checkCanSelectFromColumns(" + table.getSchemaTableName().getTableName() + ", " + columns + ")");
        if (table.getSchemaTableName().getSchemaName().equals("information_schema") && hasPermission(createResource(table.getCatalogName()), identity, PrestoAccessType.USE)) {
            return;
        }
        for (RangerPrestoResource res : createResource(table, columns)) {
          if (!hasPermission(res, identity, PrestoAccessType.SELECT)) {
            AccessDeniedException.denySelectColumns(table.getSchemaTableName().getTableName(), columns);
          }
        }
    }

    /**
     * Check if identity is allowed to insert into the specified table in a catalog.
     *
     * @throws com.facebook.presto.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanInsertIntoTable(Identity identity, AccessControlContext context, CatalogSchemaTableName table)
    {
        LOG.debug("RangerSystemAccessControl.checkCanInsertIntoTable(" + table.getSchemaTableName().getTableName() + ")");
        RangerPrestoResource res = createResource(table);
        if (!hasPermission(res, identity, PrestoAccessType.INSERT)) {
          AccessDeniedException.denyInsertTable(table.getSchemaTableName().getTableName());
        }
    }

    /**
     * Check if identity is allowed to delete from the specified table in a catalog.
     *
     * @throws com.facebook.presto.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanDeleteFromTable(Identity identity, AccessControlContext context, CatalogSchemaTableName table)
    {
        LOG.debug("RangerSystemAccessControl.checkCanDeleteFromTable(" + table.getSchemaTableName().getTableName() + ")");
        if (!hasPermission(createResource(table), identity, PrestoAccessType.DELETE)) {
          AccessDeniedException.denyDeleteTable(table.getSchemaTableName().getTableName());
        }
    }

    /**
     * Check if identity is allowed to truncate the specified table in a catalog.
     *
     * @throws com.facebook.presto.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanTruncateTable(Identity identity, AccessControlContext context, CatalogSchemaTableName table)
    {
        LOG.debug("RangerSystemAccessControl.checkCanTruncateTable(" + table.getSchemaTableName().getTableName() + ")");
        if (!hasPermission(createResource(table), identity, PrestoAccessType.DELETE)) {
          AccessDeniedException.denyDeleteTable(table.getSchemaTableName().getTableName());
        }
    }

    /**
     * Check if identity is allowed to create the specified view in a catalog.
     *
     * @throws com.facebook.presto.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanCreateView(Identity identity, AccessControlContext context, CatalogSchemaTableName view)
    {
        LOG.debug("RangerSystemAccessControl.checkCanCreateView(" + view.getSchemaTableName().getTableName() + ")");
        if (!hasPermission(createResource(view.getCatalogName(), view.getSchemaTableName().getSchemaName()), identity, PrestoAccessType.CREATE)) {
          AccessDeniedException.denyCreateView(view.getSchemaTableName().getTableName());
        } 
    }

    /**
     * Check if identity is allowed to drop the specified view in a catalog.
     *
     * @throws com.facebook.presto.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanDropView(Identity identity, AccessControlContext context, CatalogSchemaTableName view)
    {
        LOG.debug("RangerSystemAccessControl.checkCanDropView(" + view.getSchemaTableName().getTableName() + ")");
        if (!hasPermission(createResource(view), identity, PrestoAccessType.DROP)) {
          AccessDeniedException.denyDropView(view.getSchemaTableName().getTableName());
        }
    }

    /**
     * Check if identity is allowed to create a view that selects from the specified columns in a relation.
     *
     * @throws com.facebook.presto.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanCreateViewWithSelectFromColumns(Identity identity, AccessControlContext context, CatalogSchemaTableName table, Set<String> columns)
    {
        LOG.debug("RangerSystemAccessControl.checkCanCreateViewWithSelectFromColumns(" + table.getSchemaTableName().getTableName() + ", " + columns + ")");
        try {
          checkCanCreateView(identity, context, table);
        } catch (AccessDeniedException ade) {
          AccessDeniedException.denyCreateViewWithSelect(table.getSchemaTableName().getTableName(), identity);
        }
    }

    /**
     * Check if identity is allowed to set the specified property in a catalog.
     *
     * @throws com.facebook.presto.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanSetCatalogSessionProperty(Identity identity, AccessControlContext context, String catalogName, String propertyName)
    {
        LOG.debug("RangerSystemAccessControl.checkCanSetCatalogSessionProperty(" + catalogName + ", " + propertyName + ")");
        if (!hasPermission(createCatalogSessionResource(catalogName, propertyName), identity, PrestoAccessType.ALTER)) {
          AccessDeniedException.denySetCatalogSessionProperty(catalogName, propertyName);
        }
    }

    /**
     * Check if identity is allowed to grant the specified privilege to the grantee on the specified table.
     *
     * @throws com.facebook.presto.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanGrantTablePrivilege(Identity identity, AccessControlContext context, Privilege privilege, CatalogSchemaTableName table, PrestoPrincipal grantee, boolean withGrantOption)
    {
        LOG.debug("RangerSystemAccessControl.checkCanGrantTablePrivilege(" + table.getSchemaTableName().getTableName() + ")");
        if (!hasPermission(createResource(table), identity, PrestoAccessType.GRANT)) {
          AccessDeniedException.denyGrantTablePrivilege(privilege.toString(), table.toString());
        }
    }

    /**
     * Check if identity is allowed to revoke the specified privilege on the specified table from the revokee.
     *
     * @throws com.facebook.presto.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanRevokeTablePrivilege(Identity identity, AccessControlContext context, Privilege privilege, CatalogSchemaTableName table, PrestoPrincipal revokee, boolean grantOptionFor)
    {
        LOG.debug("RangerSystemAccessControl.checkCanRevokeTablePrivilege(" + table.getSchemaTableName().getTableName() + ")");
        if (!hasPermission(createResource(table), identity, PrestoAccessType.REVOKE)) {
          AccessDeniedException.denyRevokeTablePrivilege(privilege.toString(), table.toString());
        }
    }
}

class RangerPrestoResource
  extends RangerAccessResourceImpl {


  public static final String KEY_CATALOG = "catalog";
  public static final String KEY_SCHEMA = "schema";
  public static final String KEY_TABLE = "table";
  public static final String KEY_COLUMN = "column";
  public static final String KEY_USER = "prestouser";
  public static final String KEY_FUNCTION = "function";
  public static final String KEY_PROCEDURE = "procedure";
  public static final String KEY_SYSTEM_PROPERTY = "systemproperty";
  public static final String KEY_SESSION_PROPERTY = "sessionproperty";

  public RangerPrestoResource() {
  }

  public RangerPrestoResource(String catalogName, Optional<String> schema, Optional<String> table) {
    setValue(KEY_CATALOG, catalogName);
    if (schema.isPresent()) {
      setValue(KEY_SCHEMA, schema.get());
    }
    if (table.isPresent()) {
      setValue(KEY_TABLE, table.get());
    }
  }

  public RangerPrestoResource(String catalogName, Optional<String> schema, Optional<String> table, Optional<String> column) {
    setValue(KEY_CATALOG, catalogName);
    if (schema.isPresent()) {
      setValue(KEY_SCHEMA, schema.get());
    }
    if (table.isPresent()) {
      setValue(KEY_TABLE, table.get());
    }
    if (column.isPresent()) {
      setValue(KEY_COLUMN, column.get());
    }
  }

  public String getCatalogName() {
    return (String) getValue(KEY_CATALOG);
  }

  public String getTable() {
    return (String) getValue(KEY_TABLE);
  }

  public String getCatalog() {
    return (String) getValue(KEY_CATALOG);
  }

  public String getSchema() {
    return (String) getValue(KEY_SCHEMA);
  }

  public Optional<SchemaTableName> getSchemaTable() {
    final String schema = getSchema();
    if (StringUtils.isNotEmpty(schema)) {
      return Optional.of(new SchemaTableName(schema, Optional.ofNullable(getTable()).orElse("*")));
    }
    return Optional.empty();
  }
}


class RangerPrestoAccessRequest
  extends RangerAccessRequestImpl {
  public RangerPrestoAccessRequest(RangerPrestoResource resource,
                                   String user,
                                   Set<String> userGroups,
                                   PrestoAccessType prestoAccessType) {
    super(resource, prestoAccessType.name().toLowerCase(ENGLISH), user, userGroups, null);
    setAccessTime(new Date());
  }
}

enum PrestoAccessType {
  CREATE, DROP, SELECT, INSERT, DELETE, USE, ALTER, ALL, GRANT, REVOKE, SHOW, IMPERSONATE, EXECUTE;
}
