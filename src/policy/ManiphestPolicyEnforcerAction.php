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

    $policy = new PhabricatorPolicy();

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

    $policy->setRules($rules)
      ->setDefaultAction(PhabricatorPolicy::ACTION_DENY)
      ->save();

    $adapter->queueTransaction(
      id(new ManiphestTransaction())
        ->setTransactionType(PhabricatorTransactions::TYPE_VIEW_POLICY)
        ->setNewValue($policy->getPHID()));

    $adapter->queueTransaction(
      id(new ManiphestTransaction())
        ->setTransactionType(PhabricatorTransactions::TYPE_EDIT_POLICY)
        ->setNewValue($policy->getPHID()));

    return new HeraldApplyTranscript(
      $effect,
      true,
      pht('Reset Task Security')
    );
  }

  public function renderActionDescription($value) {
    return 'Reset Security Policy';
  }

  public function getHeraldActionStandardType() {
    return self::STANDARD_NONE;
  }
}
