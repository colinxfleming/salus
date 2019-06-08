require 'ruby_audit'
require 'ruby_audit/database'
require 'ruby_audit/scanner'
require 'bundler/audit/cli'
require 'salus/scanners/base'

# RubyAudit scanner to check for CVEs in Ruby version and Rubygems version.
# https://github.com/civisanalytics/ruby_audit

module Salus::Scanners
  class RubyAudit < Base
    class InvalidRubyVulnError < StandardError; end

    def run
      # Ensure the DB is up to date
      unless Bundler::Audit::Database.update!(quiet: true)
        report_error("Error updating the ruby-audit DB!")
        return
      end

      ignore = @config.fetch('ignore', [])
      scanner = ::RubyAudit::Scanner.new

      vulns = []
      scanner.scan(ignore: ignore) do |result|
        hash = serialize_vuln(result)
        vulns.push(hash)

        # TODO: we should tabulate these vulnerabilities in the same way
        # that we tabulate CVEs for Node packages - see NodeAudit scanner.
        log(JSON.pretty_generate(hash))
      end

      report_info(:ignored_cves, ignore)
      report_info(:vulnerabilities, vulns)

      vulns.empty? ? report_success : report_failure
    end

    def should_run?
      @repository.gemfile_lock_present?
    end

    private

    def serialize_vuln(vuln)
      case vuln
      when ::RubyAudit::Scanner::UnpatchedGem
        {
          type: 'UnpatchedGem',
          name: vuln.gem.name,
          version: vuln.gem.version.to_s,
          cve: vuln.advisory.id,
          url: vuln.advisory.url,
          advisory_title: vuln.advisory.title,
          description: vuln.advisory.description,
          cvss: vuln.advisory.cvss_v2,
          osvdb: vuln.advisory.osvdb,
          patched_versions: vuln.advisory.patched_versions.map(&:to_s),
          unaffected_versions: vuln.advisory.unaffected_versions.map(&:to_s)
        }
      else
        raise InvalidRubyVulnError, "RubyAudit Scanner received a #{result} from the " \
                                    "ruby_audit gem, which it doesn't know how to handle"
      end
    end
  end
end
