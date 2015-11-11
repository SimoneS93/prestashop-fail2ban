<?php

/* 
 * Emulate fail2ban behavior for admin login
 * After some failed login, the employee is banned for some time
 */
class Module_Fail2Ban extends Module
{
    const TABLE = 'fail2ban';
    const CONFIG_KEY_MAX_RETRY = 'fail2ban_max_retry';
    const CONFIG_KEY_BAN_TIME = 'fail2ban_ban_time';
    const CONFIG_KEY_FIND_TIME = 'fail2ban_find_time';
    const CONFIG_DEFAULT_MAX_RETRY = 3;
    const CONFIG_DEFAULT_BAN_TIME = 1800; //time in seconds
    const CONFIG_DEFAULT_FIND_TIME = 600; //time in seconds
    
    private $response;


    public function __construct($name, $context)
    {
        $this->name = 'module_fail2ban';
        $this->tab = 'administration';
        $this->version = '1.0.0';
        $this->author = 'Simone Salerno';
        $this->need_instance = 0;
        $this->bootstrap = 1;
        $this->response = '';

        parent::__construct($name, $context);

        $this->displayName = $this->l('Fail2Ban');
        $this->description = $this->l('Ban employee after consecutive login fails.');
    }
    
    /**
     * Create table, update config, register hooks
     */
    public function install()
    {
        $db = Db::getInstance();
        $createTable = file_get_contents(__DIR__.'/sql/create_table.sql');
        $db->execute($createTable, false);
        Configuration::updateValue(static::CONFIG_KEY_MAX_RETRY, static::CONFIG_DEFAULT_MAX_RETRY);
        Configuration::updateValue(static::CONFIG_KEY_BAN_TIME, static::CONFIG_DEFAULT_BAN_TIME);
        Configuration::updateValue(static::CONFIG_KEY_FIND_TIME, static::CONFIG_DEFAULT_FIND_TIME);
        $this->registerHook('displayBackOfficeTop');
        
        return parent::install();
    }
    
    /**
     * Unistall
     */
    public function uninstall()
    {
        Db::getInstance()->execute(sprintf('DROP TABLE IF EXISTS %s%s', _DB_PREFIX_, static::TABLE));
        $this->unregisterHook('displayBackOfficeTop');
        
        return parent::uninstall();
    }
    
    /**
     * Render configuration form
     */
    function getContent()
    {
        //update configuration values
        if (Tools::isSubmit('submitFail2BanConfiguration')) {
            $this->updateConfiguration(static::CONFIG_KEY_BAN_TIME, ['Validate', 'isUnsignedInt'], 'must be integer');
            $this->updateConfiguration(static::CONFIG_KEY_FIND_TIME, ['Validate', 'isUnsignedInt'], 'must be integer');
            $this->updateConfiguration(static::CONFIG_KEY_MAX_RETRY, ['Validate', 'isUnsignedInt'], 'must be integer');
        }
        
        $input = array(
            $this->input(static::CONFIG_KEY_BAN_TIME, 'Ban time', 'time employee cant login, even with right password, in seconds)'),
            $this->input(static::CONFIG_KEY_MAX_RETRY, 'Max retry after which employee is banned'),
            $this->input(static::CONFIG_KEY_FIND_TIME, 'Find time', 'time employee can fail MAX RETRY attemps before being banned, in seconds')
        );
        $form = array(
            'form' => array(
                'legend' => array(
                    'title' => $this->displayName
                ),
                'input' => $input,
                'submit' => array(
                    'title' => $this->l('Save')
                )
            )
        );
        $helper = new HelperForm();
        $helper->module = $this;
        $helper->identifier = $this->identifier;
        $helper->token = Tools::getAdminTokenLite('AdminModules');
        $helper->currentIndex = AdminController::$currentIndex.'&configure='.$this->name;
        $helper->default_form_language = (int)Configuration::get('PS_LANG_DEFAULT');
        $helper->allow_employee_form_lang = true;
        $helper->toolbar_scroll = true;
        $helper->title = $this->displayName;
        $helper->submit_action = 'submitFail2BanConfiguration';
        $helper->tpl_vars = array('fields_value' => array(
            static::CONFIG_KEY_BAN_TIME => ConfigurationCore::get(static::CONFIG_KEY_BAN_TIME),
            static::CONFIG_KEY_FIND_TIME => ConfigurationCore::get(static::CONFIG_KEY_FIND_TIME),
            static::CONFIG_KEY_MAX_RETRY => ConfigurationCore::get(static::CONFIG_KEY_MAX_RETRY)
        ));
        
        return $this->response . $helper->generateForm(array($form));
    }

    /**
     * Supervision employee logins
     */
    public function hookDisplayBackOfficeTop()
    {
        $email = Tools::getValue('email');
        $passwd = Tools::getValue('passwd');
        
        if (Tools::isSubmit('submitLogin') && $email && $passwd) {
            //check if employee has been banned
            $banTime = Configuration::get(static::CONFIG_KEY_BAN_TIME);
            $employeeBanTime = $this->getEmployeeBanTime($email);
            if (time() - $employeeBanTime <= $banTime) {
                $this->kickOut();
            }
            
            //track if login fails
            $employee = new Employee();
            $isLoaded = $employee->getByEmail($email, $passwd);
            if (!$isLoaded) {
                Db::getInstance()->insert(static::TABLE, array('email' => $email));
            }
            
            //employee is to ban if NOW - $eldestAccessTime <= FIND TIME
            $findTime = ConfigurationCore::get(static::CONFIG_KEY_FIND_TIME);
            $eldestAccessTime = $this->getEmployeeEldestAccessTryTime($email);
            if ($eldestAccessTime && time() - $eldestAccessTime <= $findTime) {
                $this->ban($email);
            }
        }
    }
    
    /**
     * Take action when employee tries to login when banned
     * Since it's an AJAX request, you can't do much
     */
    private function kickOut()
    {
        //@TODO
        //it seems this actually doesn't work, but AdminLoginConroller do this, so...
        $this->context->employee->logout();
        //@TODO
        //die seems not to work properly: it stops login, but still sends
        //JSON response with url to the dashboard page
        //d() stops everything
        d('banned');
    }
    
    /**
     * Mark employee as banned
     */
    private function ban($email)
    {
        Db::getInstance()->insert(static::TABLE, ['email' => $email, 'banned' => 1]);
        $this->kickOut();
    }

    /**
     * Get time when employee has been banned
     * @param string $email
     * @return int
     */
    private function getEmployeeBanTime($email)
    {
        $query = (new DbQuery)
                ->select('MAX(access_time) AS access_time')
                ->from(static::TABLE)
                ->where('banned = 1')
                ->where(sprintf('email = "%s"', pSQL($email)));
        $queryResult = Db::getInstance()->getValue($query);
        
        return $queryResult ? strtotime($queryResult) : 0;
    }
    
    /**
     * Get eldest employee login attempt time (among the MAX_RETRY last attempts)
     * @param string $email
     * @return int
     */
    private function getEmployeeEldestAccessTryTime($email)
    {
        $maxRetry = (int)ConfigurationCore::get(static::CONFIG_KEY_MAX_RETRY);
        $email = pSQL($email);
        $query = "SELECT IF(COUNT(*) = {$maxRetry}, MIN(access_time), '0000-00-00 00:00:00') AS access_time ".
                'FROM (SELECT access_time FROM {DB_PREFIX}fail2ban '.
                "WHERE banned = 0 AND email = \"{$email}\" ".
                "ORDER BY access_time DESC LIMIT {$maxRetry}) tmp";
        $accessStats = Db::getInstance()->getRow(str_replace('{DB_PREFIX}', _DB_PREFIX_, $query));
        
        return $accessStats ? strtotime($accessStats['access_time']) : 0;
    }
    
    /**
     * Shortcut to create input array
     * @param string $name
     * @param string $label
     * @param string $hint
     * @return array
     */
    private function input($name, $label, $hint = '')
    {
        $input = array('name' => $name, 'type' => 'text', 'label' => $this->l($label));
        $hint && $input['hint'] = $hint;
        
        return $input;
    }
    
    /**
     * Update configuration via form
     * @param string $name
     * @param callable $validator
     */
    private function updateConfiguration($name, $validator = null, $msg = '')
    {
        $value = Tools::getValue($name);
        
        if ($validator === null || !is_callable($validator) || $validator($value)) {
            ConfigurationCore::updateValue($name, $value);
            $this->response .= $this->displayConfirmation(sprintf('%s updated', $name));
        } else {
            $this->response .= $this->displayError(sprintf('Error on [%s]: %s', $name, $msg));
        }
    }

    /**
     * Export configurations
     * @return array
     */
    public static function exportConfiguration()
    {
        return array(
            array(
                'name' => static::CONFIG_KEY_MAX_RETRY,
                'label' => 'MAX RETRY',
                'validate' => array('Validate', 'isUnsignedInt'),
            ),
            array(
                'name' => static::CONFIG_KEY_FIND_TIME,
                'label' => 'FIND TIME',
                'validate' => array('Validate', 'isUnsignedInt'),
                'hint' => $this->l('Time (in seconds) over which login attemps are counted')
            ),
            array(
                'name' => static::CONFIG_KEY_BAN_TIME,
                'label' => 'BAN TIME',
                'validate' => array('Validate', 'isUnsignedInt'),
                'hint' => $this->l('Time (in seconds) that employee has to wait to login again')
            )
        );
    }
}
