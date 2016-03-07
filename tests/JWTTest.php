<?php
namespace vakata\jwt\test;

class JWTTest extends \PHPUnit_Framework_TestCase
{
	public static function setUpBeforeClass() {
	}
	public static function tearDownAfterClass() {
	}
	protected function setUp() {
	}
	protected function tearDown() {
	}

	public function testCreate() {
		$claims = [ 'test' => 'val' ];
		$token = new \vakata\jwt\JWT($claims);
		$this->assertEquals('val', $token->getClaim('test'));
		$this->assertEquals(null, $token->getClaim('nonexisting'));
		$this->assertEquals('na', $token->getClaim('nonexisting', 'na'));
		$this->assertEquals(false, $token->hasClaim('nonexisting'));
		$token->setClaim('nonexisting', 'here');
		$this->assertEquals('here', $token->getClaim('nonexisting', 'na'));
		$this->assertEquals(true, $token->hasClaim('nonexisting'));
		$this->assertEquals(false, $token->isSigned());
		$token->sign('secret');
		$this->assertEquals(true, $token->isValid());
		$this->assertEquals(false, $token->verifyHash('wrong'));
		$this->assertEquals(true, $token->verifyHash('secret'));
		$token2 = \vakata\jwt\JWT::fromString((string)$token);
		$this->assertEquals($token->getClaims(), $token2->getClaims());
		$this->assertEquals($token->getHeaders(), $token2->getHeaders());
		$this->assertEquals(true, $token2->isValid());
	}
}
