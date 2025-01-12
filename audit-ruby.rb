require 'parser/current'

class WebFrameworkSecurityScanner
  HIGH_RISK_PATTERNS = {
    regex_dos: [
      /\A\s*header\.to_s\.split\(['"]\s*,\s*['"].*\)/, 
      /\A\s*part\.split\(['"]\s*;\s*['"].*\)/,         
      /Regexp\.new\(.*params.*\)/                      
    ],
    
    
    header_parsing: [
      /parse_http_accept_header/,
      /parse_http_forwarded_header/,
      /parse_authorization_header/
    ],
    
    
    deserialization: [
      /Marshal\.load/,
      /JSON\.load/,
      /YAML\.load(?!_safe)/
    ]
  }

  def initialize(project_path)
    @project_path = project_path
    @findings = []
  end

  def scan
    ruby_files.each do |file|
      content = File.read(file)
      relative_path = file.sub("#{@project_path}/", '')

      HIGH_RISK_PATTERNS.each do |vulnerability_type, patterns|
        patterns.each do |pattern|
          if match = content.match(pattern)
            line_number = count_lines_until_match(content, match.begin(0))
            context = extract_context(content, line_number)
            
            record_finding(
              file: relative_path,
              line: line_number,
              vulnerability: vulnerability_type,
              context: context,
              pattern: pattern.source
            )
          end
        end
      end
    end

    report_findings
  end

  private

  def ruby_files
    Dir.glob("#{@project_path}/**/*.rb")
  end

  def count_lines_until_match(content, position)
    content[0..position].count("\n") + 1
  end

  def extract_context(content, line_number)
    lines = content.split("\n")
    start_line = [line_number - 2, 0].max
    end_line = [line_number + 2, lines.length - 1].min
    
    lines[start_line..end_line].join("\n")
  end

  def record_finding(finding)
    @findings << finding
  end

  def report_findings
    return puts "No high-risk vulnerabilities found." if @findings.empty?

    puts "\nPotential High-Risk Security Issues Found:"
    puts "========================================="
    
    @findings.each do |finding|
      puts "\nFile: #{finding[:file]}"
      puts "Line: #{finding[:line]}"
      puts "Type: #{finding[:vulnerability]}"
      puts "\nRelevant Code:\n#{finding[:context]}"
      puts "\nPotential Impact:"
      puts case finding[:vulnerability]
      when :regex_dos
        "Risk of ReDoS attack through unsafe string parsing"
      when :header_parsing
        "Potential DoS through header parsing vulnerability"
      when :deserialization
        "Unsafe deserialization could lead to RCE"
      end
      puts "----------------------------------------"
    end
  end
end

if __FILE__ == $0
  scanner = WebFrameworkSecurityScanner.new(ARGV[0] || '.')
  scanner.scan
end
