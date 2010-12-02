<?php

/**
 * @file
 * Drush commands for Security Review module.
 */

/**
 * Implementation of hook_drush_command().
 */
function security_review_drush_command() {
  $items = array();
  
  $items['security-review'] = array(
    'callback' => 'security_review_drush',
    'aliases' => array('secrev'),
    'description' => "Run the Security Review checklist",
  );
  $items['rainbow-load'] = array(
    'callback' => 'security_review_drush_hash_load',
    'description' => "Create and load a rainbow table",
  );
  
  return $items;
}

/**
 * Implementation of hook_drush_help().
 */
function security_review_drush_help($section) {
  switch ($section) {
    case 'drush:security-review':
      return dt("Run configuration security checks on your Drupal site.");
    case 'drush:rainbow-load':
      return dt("Creates a table and fills it with dictionary words for rainbow testing.");
  }
}

/**
 * Run checklist and display results command.
 */
function security_review_drush() {
  // Retrieve the checklist.
  $checklist = module_invoke_all('security_checks');
  
  $args = func_get_args();
  if (!empty($args) && $args[0] == 'run') {
    // Run the checklist.
    $result = security_review_run($checklist);
  }
  else {
    // Retrieve results from run of the checklist.
    $results = db_query("SELECT namespace, reviewcheck, result, lastrun, skip, skiptime, skipuid FROM {security_review}");
    while ($result = db_fetch_array($results)) {
      $checks[] = $result;
    }
    
    $rows = array();
    foreach ($checks as $check) {
      if ($check['result']) {
        $message = $checklist[$check['namespace']][$check['reviewcheck']]['success'];
        $status = 'success';
      }
      else {
        $message = $checklist[$check['namespace']][$check['reviewcheck']]['failure'];
        $status = 'error';
      }
      drush_log($message, $status);
    }
  }
}

function security_review_drush_hash_load() {
  $args = func_get_args();
  if (empty($args)) {
    drush_die('Filename required');
  }
  if (file_exists($args[0])) {
    // @todo move to .install.
    $sql = "CREATE TABLE IF NOT EXISTS security_review_rainbow (hash_id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, hash_word VARCHAR(20) NOT NULL, hash_hash VARCHAR(32))";
    db_query($sql);
    drush_log(dt("Truncating security_review_rainbow table"), 'success');
    db_query("TRUNCATE TABLE {security_review_rainbow}");
    
    $handle = fopen($args[0], 'r');
    if ($handle) {
      $count = 0;
      while (!feof($handle)) {
        $buffer = fgets($handle, 4096);
        $word = trim($buffer);
        $hash = md5($word);
        $sql = "INSERT INTO {security_review_rainbow} (hash_word, hash_hash) VALUES ('%s', '%s')";
        db_query($sql, $word, $hash);
        $count++;
      }
      fclose($handle);
      drush_log(dt('!count records inserted into rainbow table', array('!count' => $count)), 'success');
    }
  }
  else {
    drush_die('File not found');
  }
}
