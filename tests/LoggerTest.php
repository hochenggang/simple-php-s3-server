<?php

namespace S3Gateway\Tests;

use PHPUnit\Framework\TestCase;
use S3Gateway\Config;
use S3Gateway\Logger;

class LoggerTest extends TestCase
{
    use ResetsConfig;

    private string $logFile;

    protected function setUp(): void
    {
        $this->logFile = sys_get_temp_dir() . '/s3gateway_logger_test_' . uniqid() . '.log';
        // Reset Logger static state: force $logFile back to null so tests that
        // don't call init() behave as "uninitialized".
        $ref = new \ReflectionClass(Logger::class);
        $logFileProp = $ref->getProperty('logFile');
        $logFileProp->setValue(null, null);

        $this->resetConfig(sys_get_temp_dir() . '/s3gateway_logger_testdata_' . uniqid());
    }

    protected function tearDown(): void
    {
        if (file_exists($this->logFile)) {
            @unlink($this->logFile);
        }
        // Restore Logger to uninitialized state to avoid leaking into other tests.
        $ref = new \ReflectionClass(Logger::class);
        $logFileProp = $ref->getProperty('logFile');
        $logFileProp->setValue(null, null);
    }

    private function readLog(): string
    {
        if (!file_exists($this->logFile)) {
            return '';
        }
        return (string)file_get_contents($this->logFile);
    }

    public function testInitCreatesLogFile(): void
    {
        $this->assertFileDoesNotExist($this->logFile);
        Logger::init($this->logFile);
        $this->assertFileExists($this->logFile);
    }

    public function testLogIsNoOpWhenNotInitialized(): void
    {
        // Without init(), log() must silently return and not create any file.
        Logger::error('should-be-ignored');
        $this->assertFileDoesNotExist($this->logFile);
    }

    public function testErrorWritesErrorLevel(): void
    {
        Logger::init($this->logFile);
        Logger::error('boom');
        $content = $this->readLog();
        $this->assertStringContainsString('[ERROR]', $content);
        $this->assertStringContainsString('boom', $content);
    }

    public function testWarningWritesWarnLevel(): void
    {
        Logger::init($this->logFile);
        Logger::warning('careful');
        $content = $this->readLog();
        $this->assertStringContainsString('[WARN]', $content);
        $this->assertStringContainsString('careful', $content);
    }

    public function testInfoWritesInfoLevel(): void
    {
        Logger::init($this->logFile);
        Logger::info('hello');
        $content = $this->readLog();
        $this->assertStringContainsString('[INFO]', $content);
        $this->assertStringContainsString('hello', $content);
    }

    public function testDebugSkippedWhenAppDebugFalse(): void
    {
        $this->setConfigValue('APP_DEBUG', 'false');
        Logger::init($this->logFile);
        Logger::debug('hidden');
        $this->assertEquals('', $this->readLog());
    }

    public function testDebugEnabledWhenAppDebugTrue(): void
    {
        $this->setConfigValue('APP_DEBUG', 'true');
        Logger::init($this->logFile);
        Logger::debug('visible');
        $content = $this->readLog();
        $this->assertStringContainsString('[DEBUG]', $content);
        $this->assertStringContainsString('visible', $content);
    }

    public function testExceptionFormatsContextMessageAndTrace(): void
    {
        Logger::init($this->logFile);
        $e = new \RuntimeException('kaboom');
        Logger::exception($e, 'MyContext');
        $content = $this->readLog();
        $this->assertStringContainsString('MyContext', $content);
        $this->assertStringContainsString('kaboom', $content);
        $this->assertStringContainsString('Trace:', $content);
    }

    public function testExceptionUsesExceptionClassWhenContextEmpty(): void
    {
        Logger::init($this->logFile);
        $e = new \LogicException('fail');
        Logger::exception($e);
        $content = $this->readLog();
        // When context is empty, the exception class name is used as the label.
        $this->assertStringContainsString('LogicException', $content);
        $this->assertStringContainsString('fail', $content);
    }

    public function testExceptionSanitizesProjectPath(): void
    {
        Logger::init($this->logFile);
        // An exception thrown from inside the project src/ directory should have
        // its file path sanitized to [PROJECT]/... in the log.
        $projectFile = dirname(__DIR__) . '/src/SomeFile.php';
        $e = new \Exception('test', 0, null);
        // Force the file/line so the assertion is deterministic.
        $ref = new \ReflectionClass($e);
        $fileProp = $ref->getProperty('file');
        $fileProp->setValue($e, $projectFile);
        $lineProp = $ref->getProperty('line');
        $lineProp->setValue($e, 42);

        Logger::exception($e, 'Ctx');
        $content = $this->readLog();
        $this->assertStringContainsString('[PROJECT]', $content);
        $this->assertStringNotContainsString($projectFile, $content);
    }

    public function testRequestWithoutStatusCode(): void
    {
        Logger::init($this->logFile);
        Logger::request('GET', '/bucket/key');
        $content = $this->readLog();
        $this->assertStringContainsString('GET /bucket/key', $content);
        $this->assertStringNotContainsString('->', $content);
    }

    public function testRequestWithStatusCode(): void
    {
        Logger::init($this->logFile);
        Logger::request('PUT', '/bucket/key', 200);
        $content = $this->readLog();
        $this->assertStringContainsString('PUT /bucket/key -> 200', $content);
    }

    public function testLogEntriesAreAppended(): void
    {
        Logger::init($this->logFile);
        Logger::info('first');
        Logger::info('second');
        $content = $this->readLog();
        // Both lines must be present, in order.
        $this->assertStringContainsString('first', $content);
        $this->assertStringContainsString('second', $content);
        $this->assertLessThan(
            strpos($content, 'second'),
            strpos($content, 'first'),
            'first log entry must appear before second'
        );
    }

    public function testLogLineContainsUtcTimestamp(): void
    {
        Logger::init($this->logFile);
        Logger::info('ts-check');
        $content = $this->readLog();
        // Format: [YYYY-MM-DD HH:MM:SSZ] [INFO] ts-check
        $this->assertMatchesRegularExpression(
            '/\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}Z\]/',
            $content
        );
    }
}
