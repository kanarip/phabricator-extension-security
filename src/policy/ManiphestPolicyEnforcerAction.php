<?php

class ManiphestPolicyEnforcerAction extends HeraldAction {

  const TYPECONST = 'SecurityPolicy';
  const ACTIONCONST = 'SecurityPolicy';

  public function getHeraldActionName() {
    return pht('Enforce Security Policy');
  }

  public function getActionGroupKey() {
    return HeraldUtilityActionGroup::ACTIONGROUPKEY;
  }

  public function supportsObject($object) {
    return ($object instanceof ManiphestTask);
  }

  public function supportsRuleType($rule_type) {
    switch ($rule_type) {
      case HeraldRuleTypeConfig::RULE_TYPE_GLOBAL:
      case HeraldRuleTypeConfig::RULE_TYPE_PERSONAL:
        return true;
      case HeraldRuleTypeConfig::RULE_TYPE_OBJECT:
      default:
        return false;
    }
  }

  public function applyEffect($object, HeraldEffect $effect) {
    $adapter = $this->getAdapter();

    $task = $adapter->getObject();

    // ManiphestTaskAuthorPolicyRule
    // PhabricatorSubscriptionsSubscribersPolicyRule
    // PhabricatorAdministratorsPolicyRule

    $rules = array();

    $rules[] = array(
        'action' => PhabricatorPolicy::ACTION_ALLOW,
        'rule'   => 'ManiphestTaskAuthorPolicyRule',
        'value'  => null
    );

    $rules[] = array(
        'action' => PhabricatorPolicy::ACTION_ALLOW,
        'rule'   => 'PhabricatorSubscriptionsSubscribersPolicyRule',
        'value'  => null
    );

    $rules[] = array(
        'action' => PhabricatorPolicy::ACTION_ALLOW,
        'rule'   => 'PhabricatorAdministratorsPolicyRule',
        'value'  => null
    );

    $view_policy = id(new PhabricatorPolicy())
      ->loadOneWhere('phid = %s', $task->getViewPolicy());

    if ($view_policy) {
      $view_policy_rules = $view_policy->getRules();
    } else {
      $view_policy_rules = array();
    }

    $view_policy_diff = false;

    foreach ($rules as $id => $rule) {
      if (!in_array($rule, $view_policy_rules)) {
        $view_policy_diff = true;
        break;
      }
    }

    foreach ($view_policy_rules as $id => $rule) {
      if (!in_array($rule, $rules)) {
        $view_policy_diff = true;
        break;
      }
    }

    $edit_policy = id(new PhabricatorPolicy())
      ->loadOneWhere('phid = %s', $task->getEditPolicy());

    if ($edit_policy) {
      $edit_policy_rules = $edit_policy->getRules();
    } else {
      $edit_policy_rules = array();
    }

    $edit_policy_diff = false;

    foreach ($rules as $id => $rule) {
      if (!in_array($rule, $edit_policy_rules)) {
        $edit_policy_diff = true;
        break;
      }
    }

    foreach ($edit_policy_rules as $id => $rule) {
      if (!in_array($rule, $rules)) {
        $edit_policy_diff = true;
        break;
      }
    }

    if ($view_policy_diff || $edit_policy_diff) {
      $policy = id(new PhabricatorPolicy())
        ->setRules($rules)
        ->setDefaultAction(PhabricatorPolicy::ACTION_DENY)
        ->save();

      if ($view_policy_diff) {
        $adapter->queueTransaction(
          id(new ManiphestTransaction())
            ->setTransactionType(PhabricatorTransactions::TYPE_VIEW_POLICY)
            ->setNewValue($policy->getPHID()));
      }

      if ($edit_policy_diff) {
        $adapter->queueTransaction(
          id(new ManiphestTransaction())
            ->setTransactionType(PhabricatorTransactions::TYPE_EDIT_POLICY)
            ->setNewValue($policy->getPHID()));
      }

      return new HeraldApplyTranscript(
        $effect,
        true,
        pht('Reset Task Security')
      );
    }
  }

  public function renderActionDescription($value) {
    return 'Reset Security Policy';
  }

  public function getHeraldActionStandardType() {
    return self::STANDARD_NONE;
  }
}
