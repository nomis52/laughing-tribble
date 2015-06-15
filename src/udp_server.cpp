#include <signal.h>
#include <ola/Callback.h>
#include <ola/base/Array.h>
#include <ola/Clock.h>
#include <ola/Logging.h>
#include <ola/base/Flags.h>
#include <ola/base/Init.h>
#include <ola/base/SysExits.h>
#include <ola/io/SelectServer.h>
#include <ola/io/StdinHandler.h>
#include <ola/network/Socket.h>
#include <ola/network/InterfacePicker.h>
#include <ola/strings/Format.h>

#include <memory>
#include <string>

DEFINE_uint16(port, 5569, "The port to listen on");
DEFINE_uint16(packet_limit, 0, "Exit after this many packets");
DEFINE_string(mcast_group, "239.255.255.250", "The multicast IP to listen on");
DEFINE_string(mcast_iface, "", "The multicast interface to use");
DEFINE_default_bool(stdin_handler, true, "Enable stdin handler");

using ola::NewCallback;
using ola::io::SelectServer;
using ola::io::StdinHandler;
using ola::network::IPV4Address;
using ola::network::IPV4SocketAddress;
using ola::network::UDPSocket;
using ola::TimeInterval;
using std::auto_ptr;
using std::cout;
using std::endl;
using std::set;
using std::vector;

ola::TimeStamp GetTime() {
  ola::Clock clock;
  ola::TimeStamp now;
  clock.CurrentTime(&now);
  return now;
}

#define LOG_INFO OLA_INFO << GetTime() << " : "

class Server {
 public:
  Server() : m_packet_count(0) {
    if (FLAGS_stdin_handler) {
      m_stdin_handler.reset(new StdinHandler(
            &m_ss, ola::NewCallback(this, &Server::Input)));
    }
  }

  ~Server() {
    if (m_socket.get()) {
      m_socket->LeaveMulticast(m_interface.ip_address, m_mcast_group);
      m_ss.RemoveReadDescriptor(m_socket.get());
    }
  }

  bool Init() {
    if (!IPV4Address::FromString(FLAGS_mcast_group, &m_mcast_group)) {
      OLA_INFO << "Invalid mcast group " << FLAGS_mcast_group;
      return false;
    }

    ola::network::Interface interface;
    auto_ptr<ola::network::InterfacePicker> picker(
        ola::network::InterfacePicker::NewPicker());
    if (!picker->ChooseInterface(&m_interface, FLAGS_mcast_iface)) {
      OLA_INFO << "Failed to find an interface for multicasting";
      return false;
    }

    auto_ptr<UDPSocket> socket(new UDPSocket());
    if (!socket->Init()) {
      return false;
    }

    IPV4SocketAddress listen_addr(IPV4Address::WildCard(), FLAGS_port);
    if (!socket->Bind(listen_addr)) {
      return false;
    }

    socket->SetOnData(ola::NewCallback(this, &Server::ReceiveMessage));

    if (!socket->JoinMulticast(m_interface.ip_address, m_mcast_group, true)) {
      return false;
    }

    OLA_INFO << "Listening on " << listen_addr;

    m_socket.reset(socket.release());
    m_ss.AddReadDescriptor(m_socket.get());
    return true;
  }

  void Stop() {
    m_ss.Terminate();
  }

  void Run() {
    m_ss.Run();
  }

  void Input(int c) {
    switch (c) {
      case 'h':
        ShowHelp();
        break;
      case 'q':
        m_ss.Terminate();
        break;
      default:
        break;
    }
  }

 private:
  ola::io::SelectServer m_ss;
  auto_ptr<ola::io::StdinHandler> m_stdin_handler;
  ola::network::Interface m_interface;
  IPV4Address m_mcast_group;
  auto_ptr<UDPSocket> m_socket;
  unsigned int m_packet_count;

  void ReceiveMessage() {
    ola::network::IPV4SocketAddress client;

    uint8_t data[1500];
    ssize_t data_size = arraysize(data);
    if (m_socket->RecvFrom(data, &data_size, &client)) {
      LOG_INFO << "Received " << data_size << " bytes from " << client;
    } else {
      OLA_WARN << "Recv failure";
      return;
    }

    m_packet_count++;

    if (m_socket->SendTo(data, data_size, client)) {
      LOG_INFO << "SendTo: " << client;
    } else {
      OLA_WARN << "Failed to send";
    }

    if (m_packet_count && m_packet_count == FLAGS_packet_limit) {
      m_ss.Terminate();
    }
  }

  void ShowHelp() {
    cout << "--------------" << endl;
    cout << "h - Show Help" << endl;
    cout << "q - Quit" << endl;
    cout << "--------------" << endl;
  }
};

Server *g_server = NULL;

static void InteruptSignal(OLA_UNUSED int signal) {
  if (g_server) {
    g_server->Stop();
  }
}

int main(int argc, char *argv[]) {
  ola::AppInit(&argc, argv, "[options]", "UDP Multicast Listener");

  Server server;
  if (!server.Init()) {
    exit(ola::EXIT_UNAVAILABLE);
  }

  g_server = &server;
  ola::InstallSignal(SIGINT, InteruptSignal);
  server.Run();
  g_server = NULL;
}
