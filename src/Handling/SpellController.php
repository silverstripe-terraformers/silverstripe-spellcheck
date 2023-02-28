<?php

namespace SilverStripe\SpellCheck\Handling;

use SilverStripe\Control\Controller;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTP;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\i18n\i18n;
use SilverStripe\SpellCheck\Data\SpellProvider;
use SilverStripe\Security\Permission;
use SilverStripe\Security\SecurityToken;
use SilverStripe\Control\Middleware\HTTPCacheControlMiddleware;

/**
 * Controller to handle requests for spellchecking
 */
class SpellController extends Controller
{
    /**
     * Locales to spellcheck
     *
     * @var array
     * @config
     */
    private static array $locales = [];

    /**
     * Optional: define the default locale for TinyMCE instances. If not defined, the first locale in the list of
     * available locales will be used.
     *
     * @var string|bool
     * @config
     */
    private static string|bool $default_locale = false;

    /**
     * Necessary permission required to spellcheck. Set to empty or null to disable restrictions.
     *
     * @var string
     * @config
     */
    private static string $required_permission = 'CMS_ACCESS_CMSMain';

    /**
     * Enable security token for spellchecking
     *
     * @var bool
     * @config
     */
    private static bool $enable_security_token = true;

    /**
     * If true, all error messages will be returned with a 200 OK HTTP header code
     *
     * @var bool
     * @config
     */
    private static bool $return_errors_as_ok = false;

    /**
     * Dependencies required by this controller
     *
     * @var array
     * @config
     */
    private static array $dependencies = [
        'Provider' => '%$' . SpellProvider::class,
    ];

    /**
     * Spellcheck provider
     *
     * @var SpellProvider|null
     */
    protected ?SpellProvider $provider = null;

    /**
     * Parsed request data
     *
     * @var array|null Null if not set or an array if parsed
     */
    protected ?array $data = null;

    /**
     * Get the current provider
     *
     * @return SpellProvider
     */
    public function getProvider(): SpellProvider
    {
        return $this->provider;
    }

    /**
     * Gets locales to spellcheck for
     *
     * @return array
     */
    public static function get_locales(): array
    {
        // Default to current locale if none configured
        return self::config()->get('locales') ?: array(i18n::get_locale());
    }

    /**
     * Set the provider to use
     *
     * @param SpellProvider $provider
     * @return $this
     */
    public function setProvider(SpellProvider $provider): self
    {
        $this->provider = $provider;
        return $this;
    }

    /**
     * Parse the output response
     *
     * @param array|null $result Result data
     * @param int $code HTTP Response code
     */
    protected function result(?array $result, int $code = 200): HTTPResponse
    {
        $this->response->setStatusCode($code);
        $this->response->setBody(json_encode($result));
        return $this->response;
    }

    protected function success($result): HTTPResponse
    {
        return $this->result($result);
    }

    /**
     * Set the error.
     *
     * @param string $message
     * @param int $code HTTP error code
     */
    protected function error(string $message, int $code): HTTPResponse
    {
        // Some clients may require errors to be returned with a 200 OK header code
        if ($this->config()->get('return_errors_as_ok')) {
            $code = 200;
        }

        return $this->result(['error' => $message], $code);
    }

    public function index(): HTTPResponse
    {
        $this->setHeaders();

        // Check security token
        if ($this->config()->get('enable_security_token')
            && !SecurityToken::inst()->checkRequest($this->request)
        ) {
            return $this->error(
                _t(
                    __CLASS__ . '.SecurityMissing',
                    'Your session has expired. Please refresh your browser to continue.'
                ),
                400
            );
        }

        // Check permission
        $permission = self::config()->required_permission;
        if ($permission && !Permission::check($permission)) {
            return $this->error(_t(__CLASS__ . '.SecurityDenied', 'Permission Denied'), 403);
        }

        // Check data
        $data = $this->getRequestData();
        if (empty($data)) {
            return $this->error(_t(__CLASS__ . '.MissingData', "Could not get raw post data"), 400);
        }

        // Check params and request type
        if (!Director::is_ajax() || empty($data['method']) || empty($data['lang'])) {
            return $this->error(_t(__CLASS__ . '.InvalidRequest', 'Invalid request'), 400);
        }

        // Check locale
        $locale = $this->getLocale($data);
        if (!$locale) {
            return $this->error(_t(__CLASS__ . '.InvalidLocale', 'Not a supported locale'), 400);
        }

        // Check provider
        $provider = $this->getProvider();
        if (empty($provider)) {
            return $this->error(_t(__CLASS__ . '.MissingProviders', "No spellcheck module installed"), 500);
        }

        // Perform action
        try {
            $method = $data['method'];
            $words = explode(' ', $data['text'] ?? '');
            switch ($method) {
                case 'spellcheck':
                    return $this->success($this->assembleData($locale, $words));
                default:
                    return $this->error(
                        _t(
                            __CLASS__ . '.UnsupportedMethod',
                            "Unsupported method '{method}'",
                            array('method' => $method)
                        ),
                        400
                    );
            }
        } catch (SpellException $ex) {
            return $this->error($ex->getMessage(), $ex->getCode());
        }
    }

    /**
     * Assemble an output data structure that is expected for TinyMCE 4
     *
     * @see https://www.tinymce.com/docs/plugins/spellchecker/#spellcheckerresponseformat
     *
     * @param string $locale
     * @param string[] $words
     * @return array
     */
    protected function assembleData(string $locale, array $words): array
    {
        $result = [
            'words' => [],
        ];

        $misspelledWords = $this->getProvider()->checkWords($locale, $words);
        foreach ($misspelledWords as $word) {
            $result['words'][$word] = $this->getProvider()->getSuggestions($locale, $word);
        }

        return $result;
    }

    /**
     * Ensures the response has the correct headers
     */
    protected function setHeaders()
    {
        // Set headers
        HTTPCacheControlMiddleware::singleton()->setMaxAge(0);
        $this->response
            ->addHeader('Content-Type', 'application/json')
            ->addHeader('Content-Encoding', 'UTF-8')
            ->addHeader('X-Content-Type-Options', 'nosniff');
    }

    /**
     * Get request data
     *
     * @return array Parsed data with an id, method, and params key
     */
    protected function getRequestData(): array
    {
        // Check if data needs to be parsed
        if ($this->data === null) {
            // Parse data from input
            $this->data = $this->request->postVars();
        }
        return $this->data;
    }

    /**
     * Get the locale from the provided "lang" argument, which could be either a language code or locale
     *
     * @param array $data
     * @return string|false
     */
    protected function getLocale(array $data): string | false
    {
        $locale = $data['lang'];

        // Check if the locale is actually a language
        if (!str_contains($locale ?? '', '_')) {
            $locale = i18n::getData()->localeFromLang($locale);
        }

        if (!in_array($locale, self::get_locales() ?? [])) {
            return false;
        }

        return $locale;
    }
}
