<?php

/**
 * @file
 * Checks for security_review module.
 *
 */

/**
 * Check that files aren't writeable by the server.
 */
function security_review_check_file_perms() {
  $result = TRUE;
  // Extract ending folder for file directory path.
  $file_path = rtrim(variable_get('file_public_path', conf_path() . '/files'), '/');
  $file_path = substr($file_path, strrpos($file_path, '/') + 1);
  // Set files to ignore.
  $ignore = array('..', 'CVS', $file_path);
  $files = _security_review_check_file_perms_scan('.', $ignore);
  if (count($files)) {
    $result = FALSE;
  }
  return array('result' => $result, 'value' => $files);
}

function _security_review_check_file_perms_scan($directory, $ignore) {
  $items = array();
  if ($handle = opendir($directory)) {
    while (($file = readdir($handle)) !== FALSE) {
      // Don't check hidden files or ones we said to ignore.
      if ($file[0] != "." && !in_array($file, $ignore)) {
        $file = $directory . "/" . $file;
        if (is_dir($file)) {
          $items = array_merge($items, _security_review_check_file_perms_scan($file, $ignore));
          if (is_writable( $file)) {
            $items[] = preg_replace("/\/\//si", "/", $file);
          }
        }
        elseif (is_writable( $file)) {
          $items[] = preg_replace("/\/\//si", "/", $file);
        }
      }
    }
    closedir($handle);
  }
  return $items;
}

function security_review_check_file_perms_help($result = NULL) {
  $element['title'] =  t("Web server file system permissions");
  $element['descriptions'][] = t("It is dangerous to allow the web server to write to files inside the document root of your server. Doing so would allow Drupal to write files that could then be executed. An attacker might use such a vulnerability to take control of your site. An exception is the files directory which Drupal needs permission to write to in order to provide features like file attachments.");
  $element['descriptions'][] = t("<a href='!link'>Read more about file system permissions in the handbooks.</a>", array('!link' => url('http://drupal.org/node/244924')));

  $last_check = security_review_get_last_check('security_review', 'file_perms');
  if ($last_check['skip'] == '1') {
    $element['findings']['descriptions'][] = _security_review_check_skipped($last_check);
  }
  elseif ($last_check['result'] == '0') {
    if (is_null($result)) {
      $result = security_review_check_file_perms();
    }
    $element['findings']['descriptions'][] = t('It is recommended that the following files or directories be corrected.');
    foreach ($result['value'] as $file) {
      $element['findings']['items'][] = array(
        'safe' => check_plain($file),
        'raw' => $file,
      );
    }
  }
  return $element;
}

/**
 * Check for formats that do not have HTML filter that can be used by untrusted users.
 */
function security_review_check_input_formats() {
  $result = TRUE;
  global $user;
  $formats = filter_formats($user);
  $check_return_value = array();
  // Check formats that are accessible by untrusted users.
  $untrusted_roles = security_review_untrusted_roles();
  $untrusted_roles = array_keys($untrusted_roles);
  foreach ($formats as $id => $format) {
    $format_roles = filter_get_roles_by_format($format);
    $intersect = array_intersect(array_keys($format_roles), $untrusted_roles);
    if (!empty($intersect)) {
      // Untrusted users can use this format.
      $filters = filter_list_format($format->format);
      // Check format for enabled HTML filter.
      if (in_array('filter_html', array_keys($filters)) && $filters['filter_html']->status) {
        $filter = $filters['filter_html'];
        // Check for unsafe tags in allowed tags.
        $allowed_tags = $filter->settings['allowed_html'];
        $unsafe_tags = security_review_unsafe_tags();
        foreach ($unsafe_tags as $tag) {
          if (strpos($allowed_tags, '<' . $tag . '>') !== FALSE) {
            // Found an unsafe tag
            $check_return_value['tags'][$id] = $tag;
          }
        }
      }
      elseif (!in_array('filter_html_escape', array_keys($filters)) || !$filters['filter_html_escape']->status) {
        // Format is usable by untrusted users but does not contain the HTML Filter or the HTML escape.
        $check_return_value['formats'][$id] = $format;
      }
    }
  }

  if (!empty($check_return_value)) {
    $result = FALSE;
  }
  return array('result' => $result, 'value' => $check_return_value);
}

function security_review_check_input_formats_help($result = NULL) {
  $element['title'] = t('Allowed HTML tags in text formats');
  $element['descriptions'][] = t("Certain HTML tags can allow an attacker to take control of your site. Drupal's input format system makes use of a set filters to run on incoming text. The 'HTML Filter' strips out harmful tags and Javascript events and should be used on all formats accessible by untrusted users.");
  $element['descriptions'][] = t("<a href='!link'>Read more about Drupal's input formats in the handbooks.</a>", array('!link' => url('http://drupal.org/node/224921')));
  $last_check = security_review_get_last_check('security_review', 'input_formats');
  if ($last_check['skip'] == '1') {
    $element['findings']['descriptions'][] = _security_review_check_skipped($last_check);
  }
  elseif ($last_check['result'] == '0') {
    if (is_null($result)) {
      $result = security_review_check_input_formats();
    }
    if (!empty($result['value']['tags'])) {
      $element['findings']['descriptions'][] = t('<a href="!link">Review your text formats.</a>', array('!link' => url('admin/config/content/formats')));
      $element['findings']['descriptions'][] = t('It is recommended you remove the following tags from roles accessible by untrusted users.');
      foreach ($result['value']['tags'] as $tag) {
        $element['findings']['items'][] = array(
          'safe' => $tag, // Tag doesn't need filtering cause it's not user-defined.
          'raw' => $tag,
        );
      }
    }
    elseif (!empty($result['value']['formats'])) {
      $element['findings']['descriptions'][] = t('The following formats are usable by untrusted roles and do not filter or escape allowed HTML tags.');
      foreach ($result['value']['formats'] as $id => $format) {
        $element['findings']['items'][] = array(
          'html' => l($format->name, 'admin/config/content/formats/' . $format->format),
          'safe' => check_plain($format->name),
          'raw' => $format->name,
        );
      }
    }
  }
  return $element;
}

function security_review_check_error_reporting() {
  $error_level = variable_get('error_level', NULL);
  if (is_null($error_level) || intval($error_level) >= 1) {
    // When the variable isn't set, or its set to 1 or 2 errors are printed to the screen.
    $result = FALSE;
  }
  else {
    $result = TRUE;
  }
  return array('result' => $result);
}

function security_review_check_error_reporting_help($result = NULL) {
  $element['title'] = t('Error reporting');
  $element['descriptions'][] = t('As a form of hardening your site you should avoid information disclosure. Drupal by default prints errors to the screen and writes them to the log. Error messages disclose the full path to the file where the error occured.');
  if (is_null($result)) {
    $result = security_review_check_error_reporting();
  }
  if ($result['result'] === FALSE) {
    $element['findings']['descriptions'][] = t('You have error reporting set to both the screen and the log.');
    $element['findings']['descriptions'][] = t('<a href="!link">Alter error reporting settings.</a>', array('!link' => url('admin/config/development/logging')));
  }
  return $element;
}

/**
 * If private files is enabled check that the directory is not under the web root.
 *
 * There is ample room for the user to get around this check. @TODO get more sophisticated?
 */
function security_review_check_private_files() {
  // Get the default download method.
  $scheme = variable_get('file_default_scheme', '');
  // Most insecure configurations will be using the local private wrapper.
  if ($scheme == 'private') {
    $file_directory_path = variable_get('file_private_path', '');
    if (strpos($file_directory_path, '/') === 0) {
      // Path begins at root.
      $result = TRUE;
    }
    elseif (strpos($file_directory_path, '../') === 0) {
      // Path begins by moving up the system.
      $result = FALSE;
    }
    else {
      // Directory is relative (or crafty).
      $result = FALSE;
    }
  }
  else {
    return NULL;
  }
  return array('result' => $result);
}

function security_review_check_private_files_help($result = NULL) {
  $element['title'] = t('Private files');
  $element['descriptions'][] = t("If you have Drupal's private files feature enabled you should move the files directory outside of the web server's document root. While Drupal will control serving files when requested by way of content if a user knows the actual system path they can circumvent Drupal's private files feature. You can protect against this by specifying a files directory outside of the webserver root.");
  $last_check = security_review_get_last_check('security_review', 'private_files');
  if ($last_check['skip'] == '1') {
    $element['findings']['descriptions'][] = _security_review_check_skipped($last_check);
  }
  elseif ($last_check['result'] == '0') {
    $element['findings']['descriptions'][] = t('Your files directory is not outside of the server root.');
    $element['findings']['descriptions'][] = t('<a href="!link">Edit the files directory path.</a>', array('!link' => url('admin/config/media/file-system')));
  }
  return $element;
}

function security_review_check_query_errors($last_check = NULL) {
  $timestamp = NULL;
  $check_result_value = array();
  $query = db_select('watchdog', 'w')->fields('w', array('message', 'hostname'))
    ->condition('type', 'php')
    ->condition('severity', WATCHDOG_ERROR);
  if (!is_null($last_check)) {
    $query->condition('timestamp', $last_check['lastrun'], '>=');
  }
  $result = $query->execute();
  foreach ($result as $row) {
    if (strpos($row->message, 'SELECT') !== FALSE) {
      $entries[$row->hostname][] = $row;
    }
  }
  $result = TRUE;
  if (!empty($entries)) {
    foreach ($entries as $ip => $records) {
      if (count($records) > 10) {
        $check_result_value[] = $ip;
      }
    }
  }
  if (!empty($check_result_value)) {
    $result = FALSE;
  }
  else {
    // Rather than worrying the user about the idea of query errors we skip reporting a pass.
    return NULL;
  }
  return array('result' => $result, 'value' => $check_result_value);
}

function security_review_check_query_errors_help($result = NULL) {
  $element['title'] = t('Abundant query errors from the same IP');
  $element['descriptions'][] = t("Database errors triggered from the same IP may be an artifact of a malicious user attempting to probe the system for weaknesses like SQL injection or information disclosure.");
  $last_check = security_review_get_last_check('security_review', 'query_errors');
  if ($last_check['skip'] == '1') {
    $element['findings']['descriptions'][] = _security_review_check_skipped($last_check);
  }
  elseif ($last_check['result'] == '0') {
    $element['findings']['descriptions'][] = t('The following IPs were observed with an abundance of query errors.');
    if (is_null($result)) {
      $result = security_review_check_query_errors();
    }
    foreach ($result['value'] as $ip) {
      $element['findings']['items'][] = array(
        'safe' => check_plain($ip),
        'raw' => $ip,
      );
    }
  }
  return $element;
}

function security_review_check_failed_logins($last_check = NULL) {
  $result = TRUE;
  $timestamp = NULL;
  $check_result_value = array();
  $query = db_select('watchdog', 'w')->fields('w', array('message', 'hostname'))
    ->condition('type', 'php')
    ->condition('severity', WATCHDOG_NOTICE);
  if (!is_null($last_check)) {
    $query->condition('timestamp', $last_check['lastrun'], '>=');
  }
  $result = $query->execute();
  foreach ($result as $row) {
    if (strpos($row->message, 'Login attempt failed') !== FALSE) {
      $entries[$row->hostname][] = $row;
    }
  }
  if (!empty($entries)) {
    foreach ($entries as $ip => $records) {
      if (count($records) > 10) {
        $check_result_value[] = $ip;
      }
    }
  }
  if (!empty($check_result_value)) {
    $result = FALSE;
  }
  else {
    // Rather than worrying the user about the idea of failed logins we skip reporting a pass.
    return NULL;
  }
  return array('result' => $result, 'value' => $check_result_value);
}

function security_review_check_failed_logins_help($results = NULL) {
  $element['title'] = t('Abundant failed logins from the same IP');
  $element['descriptions'][] = t("Failed login attempts from the same IP may be an artifact of a malicous user attempting to brute-force their way onto your site as an authenticated user to carry out nefarious deeds. ");

  $last_check = security_review_get_last_check('security_review', 'failed_logins');
  if ($last_check['skip'] == '1') {
    $element['findings']['descriptions'][] = _security_review_check_skipped($last_check);
  }
  elseif ($last_check['result'] == '0') {
    $element['findings']['descriptions'][] = t('The following IPs were observed with an abundanced of failed login attempts.');
    if (is_null($results)) {
      $results = security_review_check_failed_logins();
    }
    foreach ($results['value'] as $ip) {
      $element['findings']['items'][] = array(
        'safe' => check_plain($ip),
        'raw' => $ip,
      );
    }
  }
  return $element;
}

/**
 * Look for admin permissions granted to untrusted roles.
 */
function security_review_check_admin_permissions() {
  $result = TRUE;
  $check_result_value = array();
  $untrusted_roles = security_review_untrusted_roles();
  $admin_perms = security_review_admin_permissions();
  // Get permissions for untrusted roles.
  $role_permissions = user_role_permissions($untrusted_roles);
  foreach ($role_permissions as $rid => $permissions) {
    $permissions = array_keys($permissions);
    $intersect = array_intersect($admin_perms, $permissions);
    if (!empty($intersect)) {
      $check_result_value[$rid] = $intersect;
    }
  }

  if (!empty($check_result_value)) {
    $result = FALSE;
  }
  return array('result' => $result, 'value' => $check_result_value);
}

function security_review_check_admin_permissions_help($results = NULL) {
  $element['title'] = t('Admin permissions');
  $element['descriptions'][] = t("Drupal's permission system is extensive and allows for varying degrees of control. Certain permissions would allow a user total control, or the ability to escalate their control, over your site and should only be granted to trusted users.");
  $element['descriptions'][] = t('<a href="!link">Read more about trusted vs. untrusted roles and permissions on CrackingDrupal.com.</a>', array('!link' => url('http://crackingdrupal.com/blog/ben-jeavons/importance-user-roles-and-permissions-site-security')));
  $last_check = security_review_get_last_check('security_review', 'admin_permissions');
  if ($last_check['skip'] == '1') {
    $element['findings']['descriptions'][] = _security_review_check_skipped($last_check);
  }
  elseif ($last_check['result'] == '0') {
    if (is_null($results)) {
      $results = security_review_check_admin_permissions();
    }
    $roles = user_roles();
    $element['findings']['descriptions'][] = t('You have granted untrusted roles the following administrative permissions that you should revoke.');
    foreach ($results['value'] as $rid => $permissions) {
      $permissions = implode(', ', $permissions);
      $html = t('<a href="!link">@name</a> has %permissions', array('!link' => url('admin/people/permissions/' . $rid), '@name' => $roles[$rid], '%permissions' => $permissions));
      $safe = t('@name has %permissions', array('@name' => $roles[$rid], $permissions));
      $element['findings']['items'][] = array(
        'html' => $html,
        'safe' => $safe,
        'raw' => $roles[$rid] . ':' . $permissions,
      );
    }
  }
  return $element;
}

function security_review_check_nodes($last_check = NULL) {
  // @todo move to checking fields?
  $result = TRUE;
  $check_result_value = array();
  $timestamp = NULL;
  /*$sql = "SELECT n.nid FROM {node} n INNER JOIN {node_revisions} r ON n.vid = r.vid WHERE r.body LIKE '%<script%' OR r.body LIKE '%<?php%'";
  $query = db_select('node', 'n')->fields('n', 'nid')
    ->join('node_revision', 'r', 'n.vid = r.vid')
    ->condition();*/
  if (!is_null($last_check)) {
    $sql .= " AND n.changed >= %d";
    $timestamp = $last_check['lastrun'];
  }
  $results = pager_query($sql, 50, 0, NULL, $timestamp);
  while ($row = db_fetch_array($results)) {
    $check_result_value[] = $row['nid'];
  }
  if (!empty($check_result_value)) {
    $result = FALSE;
  }

  return array('result' => $result, 'value' => $check_result_value);
}

function security_review_check_nodes_help($results = NULL) {
  $element['title'] = t('Dangerous tags in nodes');
  $element['descriptions'][] = t("Script and PHP code in the body of nodes does not align with Drupal best practices and may be a vulnerability if an untrusted user is allowed to edit such content. It is recommended you remove such content from the body of nodes.");

  $last_check = security_review_get_last_check('security_review', 'nodes');
  if ($last_check['skip'] == '1') {
    $element['findings']['descriptions'][] = _security_review_check_skipped($last_check);
  }
  elseif ($last_check['result'] == '0') {
    $element['findings']['descriptions'][] = t('The following nodes potentially have dangerous tags. The links go to the edit page.');
    if (is_null($results)) {
      $results = security_review_check_nodes(); // Don't pass $last_check because timestamp is wrong now.
    }
    foreach ($results['value'] as $nid) {
      // There is no access checking. We state that the use of this module should be granted to trusted users only.
      $node = node_load($nid);
      $html = t('@description found in <a href="!link">@title</a>', array('@description' => $description, '!link' => url('node/' . $node->nid . '/edit', array('query' => $destination)), '@title' => $node->title));
      $url = url('node/' . $node->nid . '/edit');
      $element['findings']['items'][] = array(
        'html' => $html, 
        'safe' => t('@description in !url', array('@description' => $description, '!url' => $url)),
        'raw' => $description . ':' . $url,
      );
    }
    $element['findings']['pager'] = theme('pager', array('tags' => NULL));
  }

  return $element;
}

function security_review_check_comments($last_check = NULL) {
  $result = TRUE;
  $check_result_value = array();
  $timestamp = NULL;
  if (module_exists('comment')) {
    $sql = "SELECT nid, cid FROM {comments} WHERE comment LIKE '%<script%' OR comment LIKE '%<?php%'";
    if (!is_null($last_check)) {
      $sql .= " AND timestamp >= %d";
      $timestamp = $last_check['lastrun'];
    }
    $results = pager_query($sql, 20, 0, NULL, $timestamp);
    while ($row = db_fetch_array($results)) {
      $check_result_value[$row['cid']] = $row['nid'];
    }
    if (!empty($check_result_value)) {
      $result = FALSE;
    }
  }
  else {
    return NULL;
  }
  return array('result' => $result, 'value' => $check_result_value);
}

function security_review_check_comments_help($results = NULL) {
  $element['title'] = t('Dangerous tags in comments');
  $element['descriptions'][] = t("There is little reason for script and PHP tags to be in comments (unless they are code examples) and could be in use maliciously.");

  $last_check = security_review_get_last_check('security_review', 'comments');
  if ($last_check['skip'] == '1') {
    $element['findings']['descriptions'][] = _security_review_check_skipped($last_check);
  }
  elseif ($last_check['result'] == '0') {
    $element['findings']['descriptions'][] = t('The following comments have dangerous tags. The links go to the edit page.');
    if (is_null($results)) {
      $results = security_review_check_comments(); // Don't pass $last_check because timestamp is wrong now.
    }
    foreach ($results['value'] as $cid => $nid) {
      $comment = comment_load($cid);
      // There is no access checking. We state that the use of this module should be granted to trusted users only.
      $node = node_load($nid);
      $title = t('!subject on !title', array('!subject' => $comment->subject, '!title' => $node->title));
      $element['findings']['items'][] = l($title, 'comment/edit/' . $cid);
    }
    $element['findings']['pager'] = theme('pager', array('tags' => NULL));
  }

  return $element;
}
