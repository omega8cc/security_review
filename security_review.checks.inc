<?php
// $Id$

/**
 * @file
 * Checks for security_review module.
 * 
 * @TODO Alter help implementations to not rerun check?
 */

/**
 * Check that files aren't writeable by the server.
 */
function security_review_check_file_perms() {
  $result = TRUE;
  $files = _security_review_check_file_perms_scan(rtrim($_SERVER['DOCUMENT_ROOT'] . base_path(), '/'));
  if (count($files)) {
    $result = FALSE;
  }
  return array('result' => $result, 'value' => $files);
}

function _security_review_check_file_perms_scan($directory) {
  $items = array();
  if ($handle = opendir($directory)) {
    while (($file = readdir($handle)) !== FALSE) {
      if ($file[0] != "." && $file != ".." && $file != 'CVS' && $file != 'files') { // @TODO actually get the user-supplied files directory
        $file = $directory . "/" . $file;
        if (is_dir($file)) {
          $items = array_merge($items, _security_review_check_file_perms_scan($file));
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

function security_review_check_file_perms_help() {
  $output .= '<h3>Web server file system permissions</h3>';
  $output .= '<p>It is dangerous to allow the web server to write to files inside the document root of your server. Doing so would allow Drupal to write files that could then be executed.</p>';
  
  $return = security_review_check_file_perms();
  if ($return['result'] == FALSE) {
    $output .= '<p>The following files and directories should be corrected.</p>';
    foreach ($return['value'] as $file) {
      $items[] = check_plain($file); 
    }
    $output .= theme('item_list', $items);
  }
  return $output;
}

/**
 * Check for formats that do not have HTML filter that can be used by untrusted users.
 */
function security_review_check_input_formats() {
  $formats = filter_formats();
  $check_return_value = array();
  // Check formats that untrusted users can use.
  $untrusted_roles = security_review_untrusted_roles();
  foreach ($formats as $id => $format) {
    $format_roles = array_filter(explode(',', $format->roles));
    $intersect = array_intersect($format_roles, $untrusted_roles);
    if (!empty($intersect)) {
      // Untrusted users can use this format.
      $filters = filter_list_format($format->format);
      // Check each format for HTML filter.
      foreach ($filters as $filter_id => $filter) {
        if ($filter_id == 'filter/0') {
          // Using HTML Filter, good! Now check allowed tags if the filter is stripping instead of escaping.
          $setting = variable_get("filter_html_" . $format->format, FILTER_HTML_STRIP);
          if ($setting == FILTER_HTML_STRIP) {
            // Check for unsafe tags in allowed tags.
            $allowed_tags = variable_get("allowed_html_" . $format->format, '');
            $unsafe_tags = security_review_unsafe_tags();
            foreach ($unsafe_tags as $tag) {
              if (strpos($allowed_tags, '<' . $tag . '>') !== FALSE) {
                // Found an unsafe tag
                $check_return_value[$id] = $tag;
              }
            }
          }
        }
      }
    }
  }
  if (empty($check_return_value)) {
    $result = TRUE;
  }
  else {
    $result = FALSE;
  }
  return array('result' => $result, 'value' => $check_return_value);
}

function security_review_check_input_formats_help() {
  $output .= '<h3>Allowed HTML tags in input formats</h3>';
  $output .= '<p>Certain HTML tags can allow an attacker to take control of your site.</p>';
  
  $return = security_review_check_input_formats();
  if ($return['result'] == FALSE) {
    $output .= '<p>It is recommended you remove the following tags from roles accessible by untrusted users.</p>';
    foreach ($return['value'] as $tag) {
      $items[] = $tag; 
    }
    $output .= theme('item_list', $items);
  }
  return $output;
}

function security_review_check_error_reporting() {
  $error_level = variable_get('error_level', NULL);
  if (is_null($error_level) || intval($error_level) == 1) {
    // When the variable isn't set, or its set to 1 errors are printed to the screen.
    $result = FALSE;
  }
  else {
    $result = TRUE; 
  }
  return array('result' => $result);
}

function security_review_check_error_reporting_help() {
  $output .= '<h3>Error reporting</h3>';
  $output .= '<p>As a form of hardening your site you should avoid information disclosure. Drupal by default prints errors to the screen and writes them to the log.</p>';
  $return = security_review_check_error_reporting();
  if ($return['value'] == FALSE) {
    $output .= '<p>You have error reporting set to both the screen and the log.</p>';
  }
  return $output;
}

function security_review_check_private_files() {
  $file_downloads = variable_get('file_downloads', FILE_DOWNLOADS_PUBLIC);
  if ($file_downloads == FILE_DOWNLOADS_PRIVATE) {
    $file_directory_path = file_directory_path();
    if (strpos($file_directory_path, '/') == 0) {
      // @TODO Also check for $_SERVER['DOCUMENT_ROOT']
      $result = TRUE;
    }
    elseif (strpos($file_directory_path, '../') == 0) {
      // @TODO Check for craftiness?
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

function security_review_check_private_files_help() {
  $output .= '<h3>Private files</h3>';
  $output .= "<p>If you have Drupal's private files feature enabled you should move the files directory outside of the web server's document root.</p>";
  $return = security_review_check_private_files();
  if ($return['result'] == FALSE) {
    $output .= '<p>Your files directory is not outside of the server root.</p>';
  }
  return $output;
}

/**
 * 
 */
function security_review_check_upload_extensions() {
  $result = TRUE;
  $check_return_value = array();
  if (module_exists('upload')) {
    // First, check if any unsafe extensions are even allowed.
    $extensions = variable_get('upload_extensions_default', NULL);
    if (!is_null($extensions)) {
      $unsafe_extensions = security_review_unsafe_extensions();
      foreach ($unsafe_extensions as $unsafe_extension) {
        if (strpos($extensions, $unsafe_extension) !== FALSE) {
          // Found an unsafe extension.
          $check_return_value[] = $unsafe_extension;
        }
      }
    }
    if (!empty($check_return_value)) {
      $result = FALSE;
      // Check if untrusted roles can upload. @TODO
      $untrusted_roles = security_review_untrusted_roles();
    }
  }
  else {
    return NULL;
  }
  return array('result' => $result, 'value' => $check_return_value);
}

function security_review_check_upload_extensions_help() {
  $output .= '<h3>Allowed upload extensions</h3>';
  $output .= "<p>The upload module allows users to attach files to content. Some extensions are considered dangerous because they can be executed in the browser.</p>";
  $return = security_review_check_upload_extensions();
  if ($return['result'] == FALSE) {
    $output .= '<p>The following extensions are considered unsafe.</p>';
    foreach ($return['value'] as $extension) {
      $items[] = $extension; 
    }
    $output .= theme('item_list', $items);
  }
  return $output;
}

function security_review_check_query_errors($last_check = NULL) {
  $timestamp = NULL;
  $sql = "SELECT message, hostname FROM {watchdog} WHERE type = 'php' AND severity = %d";
  if (!is_null($last_check)) {
    $sql .= " AND timestamp >= %d";
    $timestamp = $last_check['lastrun'];
  }
  $results = db_query($sql, WATCHDOG_ERROR, $timestamp);
  while ($row = db_fetch_array($results)) {
    if (strpos($row['message'], 'SELECT') !== FALSE) {
      $entries[$row['hostname']][] = $row;
    }
  }
  $result = TRUE;
  if (!empty($entries)) {
    foreach ($entries as $ip => $records) {
      if (count($records) > 10) {
        $result = FALSE;
        break;
      }
    }
  }
  // Rather than worrying the user about some query errors we skip reporting a pass.
  if ($result == TRUE) {
    return NULL;
  }
  return array('result' => $result);
}

function security_review_check_query_errors_help() {
  $output .= '<h3>Abundant query errors from the same IP</h3>';
  $output .= "<p>Database errors triggered from the same IP may be an artifact of a malicious user attempting to probe the system.</p>";
  
  return $output;
}

function security_review_check_failed_logins($last_check = NULL) {
  $timestamp = NULL;
  $sql = "SELECT message, hostname FROM {watchdog} WHERE type = 'user' AND severity = %d";
  if (!is_null($last_check)) {
    $sql .= " AND timestamp >= %d";
    $timestamp = $last_check['lastrun'];
  }
  $results = db_query($sql, WATCHDOG_NOTICE, $timestamp);
  while ($row = db_fetch_array($results)) {
    if (strpos($row['message'], 'Login attempt failed') !== FALSE) {
      $entries[$row['hostname']][] = $row;
    }
  }
  $result = TRUE;
  if (!empty($entries)) {
    foreach ($entries as $ip => $records) {
      if (count($records) > 10) {
        $result = FALSE;
        break;
      }
    }
  }
  // Rather than worrying the user about some failed logins we skip reporting a pass.
  if ($result == TRUE) {
    return NULL;
  }
  return array('result' => $result);
}

function security_review_check_failed_logins_help() {
  $output .= '<h3>Abundant failed logins from the same IP</h3>';
  $output .= "<p>Failed login attempts from the same IP may be an artifact of a malicous user attempting to.</p>";
  
  return $output;
}

function security_review_check_permissions() {
  $result = TRUE;
  $check_result_value = array();
  // Look for admin permissions granted to untrusted roles.
  $untrusted_roles = security_review_untrusted_roles();
  $admin_perms = security_review_admin_permissions();
  foreach ($untrusted_roles as $rid) {
    $perms = array();
    $results = db_fetch_array(db_query('SELECT r.rid, p.perm FROM {role} r LEFT JOIN {permission} p ON r.rid = p.rid WHERE r.rid = %d', $rid));
    if ($results !== FALSE) {
      $perms = explode(',', str_replace(', ', ',', $results['perm']));
      $intersect = array_intersect($perms, $admin_perms);
      if (!empty($intersect)) {
        $result = FALSE;
        $check_result_value = $intersect;
      }
    }
  }
  return array('result' => $result, 'value' => $check_result_value);
}

function security_review_check_permissions_help() {
  $output .= '<h3>Permissions</h3>';
  $output .= "<p>Some of the permissions provided by Drupal would allow site-takeover by the depth of control the permission grants.</p>";
  $return = security_review_check_permissions();
  if ($return['result'] == FALSE) {
    $output .= '<p>You have granted untrusted roles the following administrative permissions that you should revoke.</p>';
    $output .= theme('item_list', $return['value']);
  }
  return $output;
}

function security_review_check_nodes($last_check = NULL) {
  $result = TRUE;
  $check_result_value = array();
  $timestamp = NULL;
  $sql = "SELECT DISTINCT(nid) FROM {node_revisions} WHERE body LIKE '%<script%' OR body LIKE '%<?php%'";
  if (!is_null($last_check)) {
    $sql .= " AND timestamp >= %d";
    $timestamp = $last_check['lastrun'];
  }
  $results = db_query($sql, $timestamp);
  while ($row = db_fetch_array($results)) {
    $check_result_value[] = $row['nid'];
  }
  if (!empty($check_result_value)) {
    $result = FALSE;
  }
  
  return array('result' => $result, 'value' => $check_result_value);
}

function security_review_check_nodes_help() {
  $output .= '<h3>Dangerous tags in nodes</h3>';
  $output .= "<p>Script and PHP code in the body of nodes does not align with Drupal best practices and can potentially be a vulnerability. It is recommended you remove such content from the body of nodes.</p>";
  
  $last_check = security_review_get_last_check('security_review', 'nodes');
  if ($last_check['result'] == FALSE) {
    $output .= '<p>The following nodes have dangerous tags. The links go to the edit page.</p>';
    $return = security_review_check_nodes($last_check);
    // @TODO pager?
    foreach ($return['value'] as $nid) {
      $node = node_load($nid);
      $items[] = l($node->title, 'node/' . $node->nid . '/edit');
    }
    $output .= theme('item_list', $items);
  }
  
  return $output;
}

function security_review_check_comments($last_run) {
  $result = TRUE;
  $check_result_value = array();
  $timestamp = NULL;
  if (module_exists('comment')) {
  $sql = "SELECT nid, cid FROM {comments} WHERE comment LIKE '%<script%' OR comment LIKE '%<?php%'";
    if (!is_null($last_check)) {
      $sql .= " AND timestamp >= %d";
      $timestamp = $last_check['lastrun'];
    }
    $results = db_query($sql, $timestamp);
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

function security_review_check_comments_help() {
  $output .= '<h3>Dangerous tags in comments</h3>';
  $output .= "<p>There is little reason for script and PHP tags to be in comments (unless they are code examples) and could be in use maliciously.</p>";
  
  $last_check = security_review_get_last_check('security_review', 'comments');
  if ($last_check['result'] == FALSE) {
    $output .= '<p>The following comments have dangerous tags. The links go to the edit page.</p>';
    $return = security_review_check_comments($last_check);
    // @TODO pager?
    foreach ($return['value'] as $cid => $nid) {
      $comment = _comment_load($cid);
      $node = node_load($nid);
      $title = t('!subject on !title', array('!subject' => $comment->subject, '!title' => $node->title));
      $items[] = l($title, 'comment/edit/' . $cid);
    }
    $output .= theme('item_list', $items);
  }
  
  return $output;
}