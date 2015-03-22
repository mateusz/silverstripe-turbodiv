<?php
/**
 * ATTENTION!
 * Using this extension without the Turbodiv proxy running in front of your server is DANGEROUS.
 * You may end up exposing secure content to unauthorised users.
 */

class TurbodivExtension extends Extension {

	public function Turbodiv() {
		// Return a wrapper object, so we can provide nice dynamic property accessors.
		return new TurbodivExtension_Properties($this->owner->request);
	}

	/**
	 * Inject a highest-priority policy. Turbodiv requires we inject Vary headers for the Turbodiv
	 * partitioning properties, so the cache in front knows what should it partition by.
	 */
	public function onBeforeInit() {
		if ($this->owner->hasMethod('getPolicies')) {
			$policies = $this->owner->policies;
			array_unshift($policies, new TurbodivExtension_Policy());
			$this->owner->policies = $policies;
		}
	}

}

class TurbodivExtension_Properties extends ViewableData {

	public $request;

	public function __construct($request) {
		$this->request = $request;
	}

	public function __get($property) {
		foreach ($this->request->getHeaders() as $name => $value) {
			if ($name==="Turbodiv-$property") {
				// Reject false-y values.
				if (!trim($value)) return null;

				if ($property==='Member') {
					// Magic conversion into the actual member record.
					// We assume here that Turbodiv is running in front as a proxy, and will stop any potential
					// attackers trying to inject Turbodiv-Member headers. Running this extension without Turbodiv
					// in front is not safe!
					return Member::get()->byID((int)$value);
				}

				// If no magic required, return the header value directly.
				return $value;
			}
		}
	}

}

/**
 * Policy to inject Vary headers for all properties handled by Turbodiv.
 * These properties have been provided by the partitioner, so we are notifying
 * transparent caches that we do want to partition using these headers.
 */
class TurbodivExtension_Policy implements ControllerPolicy {

	public function applyToResponse($originator, SS_HTTPRequest $request, SS_HTTPResponse $response, DataModel $model) {
		// Collect turbodiv properties.
		$turbodivProperties = array();
		foreach ($request->getHeaders() as $name => $value) {
			if (strpos($name, 'Turbodiv-')===0) $turbodivProperties[] = $name;
		}

		// Merge vary headers, even the false-y ones.
		$originalVary = $response->getHeader('Vary');
		if (!empty($originalVary)) {
			$newVary = "$originalVary, " . implode(', ', $turbodivProperties);
		} else {
			$newVary = implode(', ', $turbodivProperties);
		}

		$response->addHeader('Vary', $newVary);
	}

}
