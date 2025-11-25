import { useState, useEffect, useRef } from 'react';
import { useRouter } from 'next/router';
import axios from 'axios';
import { io, Socket } from 'socket.io-client';
import styles from '../styles/index.module.css';
import notificationStyles from '../styles/Notification.module.css';
import AIChat from '../components/AIChat';
import AlertBox, { AlertType } from '../components/AlertBox';
import Notification, { NotificationProps } from '../components/Notification';

const API_BASE = (typeof window !== 'undefined' && (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'))
  ? 'http://localhost:3001/api'
  : '/api';

type ViewMode = 'dashboard' | 'diary' | 'ai-chat' | 'mod-chat' | 'admin' | 'friends' | 'settings';

export default function Home() {
  const router = useRouter();
  const [token, setToken] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [nickname, setNickname] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [mood, setMood] = useState(3);
  const [note, setNote] = useState('');
  const [demoMood, setDemoMood] = useState(3);
  const [demoNote, setDemoNote] = useState('');
  const [demoPreview, setDemoPreview] = useState<{ mood: number; note: string; createdAt: string }[]>([]);
  const [entries, setEntries] = useState<any[]>([]);
  const [loginMethod, setLoginMethod] = useState<'anonymous' | 'login' | 'register'>('anonymous');
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const [messages, setMessages] = useState<{ sender: string; message: string; timestamp: string }[]>([]);
  const [newMessage, setNewMessage] = useState('');
  const [socket, setSocket] = useState<Socket | null>(null);
  const [isAdmin, setIsAdmin] = useState(false);
  const [helpRequested, setHelpRequested] = useState(false);
  const [privateChat, setPrivateChat] = useState<{ active: boolean; adminId?: string; nickname?: string }>({
    active: false,
  });
  const [helpRequests, setHelpRequests] = useState<{ userId: string; nickname: string }[]>([]);
  const [adminDropdownOpen, setAdminDropdownOpen] = useState(false);
  const [chatOpen, setChatOpen] = useState(false);
  const [aiChatOpen, setAiChatOpen] = useState(false);
  const [alertBox, setAlertBox] = useState<AlertType | null>(null);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [currentView, setCurrentView] = useState<ViewMode>('dashboard');
  const [sidebarProfileOpen, setSidebarProfileOpen] = useState(false);
  const [notifications, setNotifications] = useState<NotificationProps[]>([]);
  
  const [friends, setFriends] = useState<any[]>([]);
  const [friendRequests, setFriendRequests] = useState<any[]>([]);
  const [selectedFriend, setSelectedFriend] = useState<any>(null);
  const [friendMessages, setFriendMessages] = useState<any[]>([]);
  const [newFriendMessage, setNewFriendMessage] = useState('');
  const [friendUsername, setFriendUsername] = useState('');
  const [friendStats, setFriendStats] = useState<any>(null);
  
  const [showAllEntriesModal, setShowAllEntriesModal] = useState(false);
  
  const [twoFactorEnabled, setTwoFactorEnabled] = useState(false);
  const [twoFactorQR, setTwoFactorQR] = useState('');
  const [twoFactorSecret, setTwoFactorSecret] = useState('');
  const [twoFactorCode, setTwoFactorCode] = useState('');
  const [twoFactorSetupActive, setTwoFactorSetupActive] = useState(false);
  const [loginTwoFactorCode, setLoginTwoFactorCode] = useState('');
  const [requiresTwoFactor, setRequiresTwoFactor] = useState(false);
  
  const [unreadMessagesCount, setUnreadMessagesCount] = useState(0);
  
  const [inputModal, setInputModal] = useState<{
    isOpen: boolean;
    title: string;
    fields: { name: string; label: string; type: string; placeholder: string; maxLength?: number }[];
    onSubmit: (values: Record<string, string>) => void;
    onCancel: () => void;
  } | null>(null);
  
  const dropdownRef = useRef<HTMLDivElement>(null);
  const adminDropdownRef = useRef<HTMLDivElement>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const friendMessagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const savedToken = typeof window !== 'undefined' ? (localStorage.getItem('token') || sessionStorage.getItem('token')) : null;
    const savedNick = typeof window !== 'undefined' ? (localStorage.getItem('nickname') || sessionStorage.getItem('nickname')) : null;
    
    if (savedNick) setNickname(savedNick);
    if (savedToken) {
      setToken(savedToken);
      axios
        .get(`${API_BASE}/mood`, { headers: { Authorization: `Bearer ${savedToken}` } })
        .then((res) => setEntries(res.data))
        .catch(() => {});
      axios
        .get(`${API_BASE}/admin/users`, { headers: { Authorization: `Bearer ${savedToken}` } })
        .then(() => setIsAdmin(true))
        .catch(() => setIsAdmin(false));
    } else {
      router.push('/main');
    }
    setIsLoading(false);
  }, [router]);

  useEffect(() => {
    console.log('Notifications state updated:', notifications);
  }, [notifications]);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setDropdownOpen(false);
      }
      if (adminDropdownRef.current && !adminDropdownRef.current.contains(event.target as Node)) {
        setAdminDropdownOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  useEffect(() => {
    if (!token) return;
    const newSocket = io('http://localhost:3001', { auth: { token }, transports: ['websocket'] });
    setSocket(newSocket);

    newSocket.on('helpRequestReceived', () => {
      console.log('Help request confirmed by server');
    });

    newSocket.on('adminConnected', (data: { adminId: string; nickname: string }) => {
      console.log('Admin connected:', data);
      setPrivateChat({ active: true, adminId: data.adminId, nickname: data.nickname });
      setHelpRequested(false);
      setChatOpen(true);
    });

    newSocket.on('privateMessage', (data: { from: string; message: string; timestamp: string; senderNickname?: string }) => {
      console.log('Private message received:', data);
      const isMyMessage = data.from === newSocket.id;
      setMessages((prev) => [
        ...prev,
        {
          sender: isMyMessage ? 'Ja' : (data.senderNickname || 'Rozmówca'),
          message: data.message,
          timestamp: data.timestamp,
        },
      ]);
      setTimeout(() => {
        messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
      }, 100);
    });

    newSocket.on('helpRequests', (requests: { userId: string; nickname: string }[]) => {
      console.log('Help requests received:', requests);
      console.log('Current helpRequests length:', helpRequests.length);
      console.log('New requests length:', requests.length);
      
      setHelpRequests(prevRequests => {
        const newRequests = requests.filter(req => 
          !prevRequests.some(prev => prev.userId === req.userId)
        );
        
        console.log('New requests to notify:', newRequests);
        
        if (newRequests.length > 0) {
          setNotifications(prev => {
            const existingNotificationUserIds = new Set(
              prev.filter(n => n.id.startsWith('help-')).map(n => n.id.split('help-')[1])
            );
            
            const notificationsToAdd = newRequests
              .filter(req => !existingNotificationUserIds.has(req.userId))
              .map(newRequest => ({
                id: `help-${newRequest.userId}`,
                title: 'Nowa prośba o pomoc',
                message: `${newRequest.nickname} prosi o rozmowę z moderatorem`,
                onClose: (id: string) => setNotifications(prev => prev.filter(n => n.id !== id)),
                onAccept: (id: string) => {
                  console.log('Accepting help request for:', newRequest.userId);
                  if (newSocket) {
                    newSocket.emit('adminConnect', { userId: newRequest.userId });
                    setAdminDropdownOpen(false);
                    setCurrentView('mod-chat');
                  }
                },
                autoClose: 8000
              }));
            
            return [...prev, ...notificationsToAdd];
          });
        }
        return requests;
      });
    });

    newSocket.on('adminConnectedToUser', (data: { userId: string; userSocketId: string; userNickname: string }) => {
      console.log('Admin connected to user:', data);
      setPrivateChat({ active: true, adminId: data.userSocketId, nickname: data.userNickname });
      setChatOpen(true);
      setCurrentView('mod-chat');
    });

    newSocket.on('userDisconnected', (data: { nickname?: string }) => {
      console.log('User disconnected:', data);
      setAlertBox({
        type: 'info',
        message: `${data.nickname || 'Użytkownik'} opuścił czat.`,
        onConfirm: () => {
          setAlertBox(null);
          setPrivateChat({ active: false });
          setMessages([]);
          setCurrentView('dashboard');
        }
      });
    });

    newSocket.on('chatEnded', (data: { nickname?: string }) => {
      console.log('Chat ended by:', data);
      setAlertBox({
        type: 'info',
        message: `${data.nickname || 'Rozmówca'} zakończył czat.`,
        onConfirm: () => {
          setAlertBox(null);
          setPrivateChat({ active: false });
          setMessages([]);
          setCurrentView('dashboard');
        }
      });
    });

    newSocket.on('friendRequestReceived', (data: { id: string; sender: any; createdAt: string }) => {
      console.log('Friend request received:', data);
      setNotifications(prev => [...prev, {
        id: `friend-request-${data.id}`,
        title: 'Nowe zaproszenie do znajomych',
        message: `${data.sender.nickname} chce dodać Cię do znajomych`,
        onClose: (id: string) => setNotifications(prev => prev.filter(n => n.id !== id)),
        onAccept: async (id: string) => {
          try {
            await axios.post(`${API_BASE}/friends/accept`, { requestId: data.id }, {
              headers: { Authorization: `Bearer ${token}` }
            });
            setNotifications(prev => prev.filter(n => n.id !== id));
            loadFriends();
            loadFriendRequests();
          } catch (err) {
            console.error('Error accepting friend request:', err);
          }
        },
        onDecline: async (id: string) => {
          try {
            await axios.post(`${API_BASE}/friends/reject`, { requestId: data.id }, {
              headers: { Authorization: `Bearer ${token}` }
            });
            setNotifications(prev => prev.filter(n => n.id !== id));
            loadFriendRequests();
          } catch (err) {
            console.error('Error rejecting friend request:', err);
          }
        },
        autoClose: 0,
      }]);
      loadFriendRequests();
    });

    newSocket.on('friendRequestAccepted', (data: { friend: any }) => {
      console.log('Friend request accepted:', data);
      setNotifications(prev => [...prev, {
        id: `friend-accepted-${Date.now()}`,
        title: 'Zaproszenie zaakceptowane',
        message: `${data.friend.nickname} zaakceptował Twoje zaproszenie do znajomych`,
        onClose: (id: string) => setNotifications(prev => prev.filter(n => n.id !== id)),
        autoClose: 5000,
      }]);
      loadFriends();
    });

    newSocket.on('friendRemoved', (data: { friendId: string; nickname: string }) => {
      console.log('Friend removed:', data);
      if (selectedFriend && selectedFriend.id === data.friendId) {
        setSelectedFriend(null);
        setFriendMessages([]);
      }
      loadFriends();
      setNotifications(prev => [...prev, {
        id: `friend-removed-${Date.now()}`,
        title: 'Usunięto ze znajomych',
        message: `${data.nickname} usunął Cię ze znajomych`,
        onClose: (id: string) => setNotifications(prev => prev.filter(n => n.id !== id)),
        autoClose: 5000,
      }]);
    });

    newSocket.on('directMessage', (data: { id: string; sender: any; content: string; createdAt: string }) => {
      console.log('Direct message received:', data);
      
      if (selectedFriend && data.sender.id === selectedFriend.id) {
        setFriendMessages(prev => [...prev, {
          id: data.id,
          sender: data.sender,
          content: data.content,
          createdAt: data.createdAt,
        }]);
        setTimeout(() => {
          friendMessagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
        }, 100);
      } else {
        setUnreadMessagesCount(prev => prev + 1);
        
        setNotifications(prev => [...prev, {
          id: `dm-${data.id}`,
          title: 'Nowa wiadomość',
          message: `${data.sender.nickname}: ${data.content.substring(0, 50)}${data.content.length > 50 ? '...' : ''}`,
          onClose: (id: string) => setNotifications(prev => prev.filter(n => n.id !== id)),
          onAccept: async (id: string) => {
            setCurrentView('friends');
            const friend = friends.find(f => f.id === data.sender.id);
            if (friend) {
              setSelectedFriend(friend);
              await loadFriendMessages(friend.id);
            }
            setNotifications(prev => prev.filter(n => n.id !== id));
          },
          autoClose: 8000,
        }]);
      }
    });

    newSocket.on('connect', () => {
      console.log('Socket connected:', newSocket.id);
    });

    newSocket.on('disconnect', () => {
      console.log('Socket disconnected');
    });

    return () => {
      newSocket.disconnect();
    };
  }, [token, selectedFriend, friends]);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const loginData: any = { nickname: email, password };
      
      if (requiresTwoFactor && loginTwoFactorCode) {
        loginData.twoFactorCode = loginTwoFactorCode;
      }
      
      const res = await axios.post(`${API_BASE}/auth/login`, loginData);

      if (res.data.requires2FA) {
        setRequiresTwoFactor(true);
        setAlertBox({
          type: 'info',
          message: 'Wprowadź kod z aplikacji Authy',
          onConfirm: () => setAlertBox(null)
        });
        return;
      }

      if (res.data.error) {
        setAlertBox({
          type: 'error',
          message: res.data.error,
          onConfirm: () => setAlertBox(null)
        });
        return;
      }

      const newToken = res.data.token;
      const username = res.data.user?.nickname || email.split('@')[0];
      localStorage.setItem('token', newToken);
      localStorage.setItem('nickname', username);
      setToken(newToken);
      fetchMoodEntries(newToken);
      
      setRequiresTwoFactor(false);
      setLoginTwoFactorCode('');

      axios.get(`${API_BASE}/admin/users`, {
        headers: { Authorization: `Bearer ${newToken}` },
      })
        .then(() => setIsAdmin(true))
        .catch(() => setIsAdmin(false));
    } catch (error: any) {
      const errorMessage = error.response?.data?.error || error.message || 'Logowanie nie powiodło się';
      setAlertBox({
        type: 'error',
        message: errorMessage,
        onConfirm: () => setAlertBox(null)
      });
    }
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await axios.post(`${API_BASE}/auth/register`, { nickname, email, password });
      const newToken = res.data.token;
      localStorage.setItem('token', newToken);
      localStorage.setItem('nickname', nickname);
      setToken(newToken);
      fetchMoodEntries(newToken);

      axios.get(`${API_BASE}/admin/users`, {
        headers: { Authorization: `Bearer ${newToken}` },
      })
        .then(() => setIsAdmin(true))
        .catch(() => setIsAdmin(false));
    } catch (error: any) {
      const errorMessage = error.response?.data?.error || 'Rejestracja nie powiodła się';
      setAlertBox({
        type: 'error',
        message: errorMessage,
        onConfirm: () => setAlertBox(null)
      });
    }
  };

  const handleSaveMood = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await axios.post(
        `${API_BASE}/mood`,
        { mood, note },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setNote('');
      fetchMoodEntries(token!);
    } catch (error) {
      setAlertBox({
        type: 'error',
        message: 'Nie udało się zapisać nastroju',
        onConfirm: () => setAlertBox(null)
      });
    }
  };

  const handleDeleteMood = async (id: string) => {
    setAlertBox({
      type: 'warning',
      message: 'Czy na pewno chcesz usunąć ten wpis?',
      onConfirm: async () => {
        setAlertBox(null);
        try {
          await axios.delete(`${API_BASE}/mood/${id}`, {
            headers: { Authorization: `Bearer ${token}` },
          });
          fetchMoodEntries(token!);
        } catch (error: any) {
          setAlertBox({
            type: 'error',
            message: error.response?.data?.error || 'Nie udało się usunąć wpisu',
            onConfirm: () => setAlertBox(null)
          });
        }
      },
      onCancel: () => setAlertBox(null)
    });
  };

  const fetchMoodEntries = async (token: string) => {
    try {
      const res = await axios.get(`${API_BASE}/mood`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setEntries(res.data);
    } catch (error) {
      setAlertBox({
        type: 'error',
        message: 'Nie udało się pobrać wpisów',
        onConfirm: () => setAlertBox(null)
      });
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('nickname');
    sessionStorage.removeItem('token');
    sessionStorage.removeItem('nickname');
    setToken(null);
    setEntries([]);
    setMessages([]);
    if (socket) {
      socket.disconnect();
      setSocket(null);
    }
    setIsAdmin(false);
    setHelpRequested(false);
    setHelpRequests([]);
    setPrivateChat({ active: false });
    setAdminDropdownOpen(false);
    setDropdownOpen(false);
    router.push('/login');
  };

  const getUsername = () => {
    if (nickname && nickname.trim()) return nickname;

    const storedNickname = typeof window !== 'undefined'
      ? (localStorage.getItem('nickname') || sessionStorage.getItem('nickname'))
      : null;

    if (storedNickname && storedNickname.trim()) return storedNickname;

    return 'Użytkownik';
  };

  const requestHelp = () => {
    if (!socket) {
      console.warn('requestHelp: socket is not initialized yet');
      setAlertBox({
        type: 'warning',
        message: 'Połączenie realtime jest niedostępne — spróbuj odświeżyć stronę.',
        onConfirm: () => setAlertBox(null)
      });
      return;
    }
    if (!socket.connected) {
      console.warn('requestHelp: socket exists but is not connected (reconnecting?)');
      setAlertBox({
        type: 'error',
        message: 'Socket nie jest połączony — sprawdź backend (port 3001).',
        onConfirm: () => setAlertBox(null)
      });
      return;
    }
    console.log('Sending requestHelp via socket', socket.id);
    socket.emit('requestHelp');
    setHelpRequested(true);
  };

  const connectToUser = (userId: string) => {
    if (socket) {
      socket.emit('adminConnect', { userId });
      setAdminDropdownOpen(false);
      setCurrentView('mod-chat');
    }
  };

  const sendMessage = () => {
    if (newMessage.trim() && socket && privateChat.active && privateChat.adminId) {
      socket.emit('privateMessage', {
        to: privateChat.adminId,
        message: newMessage,
      });
      setNewMessage('');
    }
  };

  const loadFriends = async () => {
    if (!token) return;
    try {
      const res = await axios.get(`${API_BASE}/friends`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setFriends(res.data);
    } catch (error) {
      console.error('Error loading friends:', error);
    }
  };

  const loadFriendRequests = async () => {
    if (!token) return;
    try {
      const res = await axios.get(`${API_BASE}/friends/requests`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setFriendRequests(res.data);
    } catch (error) {
      console.error('Error loading friend requests:', error);
    }
  };

  const sendFriendRequest = async () => {
    if (!friendUsername.trim()) return;
    try {
      await axios.post(`${API_BASE}/friends/send-request`, 
        { username: friendUsername },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setAlertBox({
        type: 'success',
        message: 'Wysłano zaproszenie do znajomych',
        onConfirm: () => setAlertBox(null),
      });
      setFriendUsername('');
    } catch (error: any) {
      setAlertBox({
        type: 'error',
        message: error.response?.data?.error || 'Nie udało się wysłać zaproszenia',
        onConfirm: () => setAlertBox(null),
      });
    }
  };

  const acceptFriendRequest = async (requestId: string) => {
    try {
      await axios.post(`${API_BASE}/friends/accept`, 
        { requestId },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      loadFriends();
      loadFriendRequests();
    } catch (error) {
      console.error('Error accepting friend request:', error);
    }
  };

  const rejectFriendRequest = async (requestId: string) => {
    try {
      await axios.post(`${API_BASE}/friends/reject`, 
        { requestId },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      loadFriendRequests();
    } catch (error) {
      console.error('Error rejecting friend request:', error);
    }
  };

  const removeFriend = async (friendId: string) => {
    setAlertBox({
      type: 'warning',
      message: 'Czy na pewno chcesz usunąć tego znajomego?',
      onConfirm: async () => {
        try {
          await axios.delete(`${API_BASE}/friends/${friendId}`, {
            headers: { Authorization: `Bearer ${token}` },
          });
          setAlertBox(null);
          loadFriends();
          setSelectedFriend(null);
        } catch (error) {
          console.error('Error removing friend:', error);
        }
      },
      onCancel: () => setAlertBox(null),
    });
  };

  const loadFriendMessages = async (friendId: string) => {
    try {
      const res = await axios.get(`${API_BASE}/friends/${friendId}/messages`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setFriendMessages(res.data);
      setTimeout(() => {
        friendMessagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
      }, 100);
    } catch (error) {
      console.error('Error loading friend messages:', error);
    }
  };

  const loadFriendStats = async (friendId: string) => {
    try {
      const res = await axios.get(`${API_BASE}/friends/${friendId}/stats`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setFriendStats(res.data);
    } catch (error) {
      console.error('Error loading friend stats:', error);
    }
  };

  const sendFriendMessage = async () => {
    if (!newFriendMessage.trim() || !selectedFriend) return;
    try {
      await axios.post(`${API_BASE}/friends/${selectedFriend.id}/messages`, 
        { content: newFriendMessage },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setNewFriendMessage('');
      await loadFriendMessages(selectedFriend.id);
      await loadUnreadMessagesCount();
    } catch (error) {
      console.error('Error sending message:', error);
    }
  };

  const loadUnreadMessagesCount = async () => {
    if (!token) return;
    try {
      const res = await axios.get(`${API_BASE}/friends/messages/unread`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setUnreadMessagesCount(res.data.unreadCount || 0);
    } catch (error) {
      console.error('Error loading unread messages count:', error);
    }
  };

  
  const setup2FA = async () => {
    try {
      const res = await axios.post(`${API_BASE}/2fa/setup`, {}, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setTwoFactorQR(res.data.qrCode);
      setTwoFactorSecret(res.data.secret);
      setTwoFactorSetupActive(true);
    } catch (error: any) {
      setAlertBox({
        type: 'error',
        message: error.response?.data?.error || 'Nie udało się skonfigurować 2FA',
        onConfirm: () => setAlertBox(null)
      });
    }
  };

  const enable2FA = async () => {
    if (!twoFactorCode.trim()) {
      setAlertBox({
        type: 'error',
        message: 'Wprowadź kod z aplikacji Authy',
        onConfirm: () => setAlertBox(null)
      });
      return;
    }

    try {
      await axios.post(`${API_BASE}/2fa/enable`, {
        secret: twoFactorSecret,
        code: twoFactorCode
      }, {
        headers: { Authorization: `Bearer ${token}` }
      });
      
      setTwoFactorEnabled(true);
      setTwoFactorSetupActive(false);
      setTwoFactorCode('');
      setTwoFactorQR('');
      setTwoFactorSecret('');
      
      setAlertBox({
        type: 'success',
        message: 'Weryfikacja dwuetapowa została włączona!',
        onConfirm: () => setAlertBox(null)
      });
    } catch (error: any) {
      setAlertBox({
        type: 'error',
        message: error.response?.data?.error || 'Nieprawidłowy kod weryfikacji',
        onConfirm: () => setAlertBox(null)
      });
    }
  };

  const disable2FA = async () => {
    setAlertBox({
      type: 'warning',
      message: 'Czy na pewno chcesz wyłączyć weryfikację dwuetapową?',
      onConfirm: async () => {
        setAlertBox(null);
        
        setInputModal({
          isOpen: true,
          title: 'Wyłącz weryfikację dwuetapową',
          fields: [
            { name: 'password', label: 'Hasło', type: 'password', placeholder: 'Wprowadź hasło' },
            { name: 'code', label: 'Kod 2FA', type: 'text', placeholder: '000000', maxLength: 6 }
          ],
          onSubmit: async (values) => {
            setInputModal(null);
            
            try {
              await axios.post(`${API_BASE}/2fa/disable`, {
                password: values.password,
                code: values.code
              }, {
                headers: { Authorization: `Bearer ${token}` }
              });
              
              setTwoFactorEnabled(false);
              
              setAlertBox({
                type: 'success',
                message: 'Weryfikacja dwuetapowa została wyłączona',
                onConfirm: () => setAlertBox(null)
              });
            } catch (error: any) {
              setAlertBox({
                type: 'error',
                message: error.response?.data?.error || 'Nie udało się wyłączyć 2FA',
                onConfirm: () => setAlertBox(null)
              });
            }
          },
          onCancel: () => setInputModal(null)
        });
      },
      onCancel: () => setAlertBox(null)
    });
  };

  const deleteAccount = async () => {
    setAlertBox({
      type: 'warning',
      message: '⚠️ OSTRZEŻENIE\n\nCzy na pewno chcesz usunąć swoje konto?\n\n• Wszystkie Twoje dane zostaną trwale usunięte\n• Ta operacja jest nieodwracalna\n• Nie będziesz mógł odzyskać swoich danych',
      onConfirm: async () => {
        setAlertBox(null);
        
        const fields: { name: string; label: string; type: string; placeholder: string; maxLength?: number }[] = [
          { name: 'password', label: 'Hasło', type: 'password', placeholder: 'Wprowadź hasło aby potwierdzić' }
        ];
        
        if (twoFactorEnabled) {
          fields.push({ name: 'twoFactorCode', label: 'Kod 2FA', type: 'text', placeholder: '000000', maxLength: 6 });
        }
        
        setInputModal({
          isOpen: true,
          title: 'Usuń konto',
          fields,
          onSubmit: async (values) => {
            setInputModal(null);
            
            try {
              await axios.delete(`${API_BASE}/account`, {
                headers: { Authorization: `Bearer ${token}` },
                data: { 
                  password: values.password,
                  twoFactorCode: values.twoFactorCode || ''
                }
              });
              
              localStorage.removeItem('token');
              localStorage.removeItem('nickname');
              sessionStorage.removeItem('token');
              sessionStorage.removeItem('nickname');
              
              setAlertBox({
                type: 'success',
                message: 'Twoje konto zostało usunięte',
                onConfirm: () => {
                  setAlertBox(null);
                  router.push('/login');
                }
              });
            } catch (error: any) {
              setAlertBox({
                type: 'error',
                message: error.response?.data?.error || 'Nie udało się usunąć konta',
                onConfirm: () => setAlertBox(null)
              });
            }
          },
          onCancel: () => setInputModal(null)
        });
      },
      onCancel: () => setAlertBox(null)
    });
  };

  useEffect(() => {
    const load2FAStatus = async () => {
      if (!token) return;
      try {
        const res = await axios.get(`${API_BASE}/2fa/status`, {
          headers: { Authorization: `Bearer ${token}` }
        });
        setTwoFactorEnabled(res.data.enabled);
      } catch (error) {
        console.error('Error loading 2FA status:', error);
      }
    };
    load2FAStatus();
  }, [token]);

  useEffect(() => {
    if (token) {
      loadUnreadMessagesCount();
      const interval = setInterval(loadUnreadMessagesCount, 30000);
      return () => clearInterval(interval);
    }
  }, [token]);

  useEffect(() => {
    if (currentView === 'friends' && token) {
      loadFriends();
      loadFriendRequests();
      loadUnreadMessagesCount();
    }
  }, [currentView, token]);

  useEffect(() => {
    if (selectedFriend && token) {
      loadFriendMessages(selectedFriend.id);
      loadFriendStats(selectedFriend.id);
    }
  }, [selectedFriend, token]);

  const AdminPanel = ({ token, helpRequests, onConnect }: { 
    token: string, 
    helpRequests: { userId: string; nickname: string }[],
    onConnect: (userId: string) => void
  }) => {
    const [users, setUsers] = useState<any[]>([]);
    const [entries, setEntries] = useState<any[]>([]);
    const [loading, setLoading] = useState(false);
    const [bannedIPs, setBannedIPs] = useState<any[]>([]);
    const [currentUserData, setCurrentUserData] = useState<any>(null);

    const fetchUsers = async () => {
      setLoading(true);
      try {
        const res = await axios.get(`${API_BASE}/admin/users`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        setUsers(res.data);
        
        const decoded: any = token ? JSON.parse(atob(token.split('.')[1])) : null;
        if (decoded) {
          const currentUser = res.data.find((u: any) => u.id === decoded.id);
          setCurrentUserData(currentUser);
        }
      } catch (error) {
        setAlertBox({
          type: 'error',
          message: 'Nie udało się pobrać użytkowników',
          onConfirm: () => setAlertBox(null)
        });
      }
      setLoading(false);
    };

    const fetchEntries = async () => {
      setLoading(true);
      try {
        const res = await axios.get(`${API_BASE}/admin/mood-entries`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        setEntries(res.data);
      } catch (error) {
        setAlertBox({
          type: 'error',
          message: 'Nie udało się pobrać wpisów',
          onConfirm: () => setAlertBox(null)
        });
      }
      setLoading(false);
    };

    const toggleBan = async (userId: string, isBanned: boolean) => {
      try {
        const endpoint = isBanned ? 'unban' : 'ban';
        await axios.post(`${API_BASE}/admin/${endpoint}`, { userId }, {
          headers: { Authorization: `Bearer ${token}` },
        });
        fetchUsers();
      } catch (error: any) {
        setAlertBox({
          type: 'error',
          message: error.response?.data?.error || 'Nie udało się zmienić statusu bana',
          onConfirm: () => setAlertBox(null)
        });
      }
    };

    const banIP = async (userId: string) => {
      setAlertBox({
        type: 'warning',
        message: 'Czy na pewno chcesz zbanować adres IP tego użytkownika? Wszystkie konta z tego IP zostaną zablokowane.',
        onConfirm: async () => {
          setAlertBox(null);
          try {
            const response = await axios.post(`${API_BASE}/admin/ban-ip`, { userId, reason: 'Zbanowany przez moderatora' }, {
              headers: { Authorization: `Bearer ${token}` },
            });
            setAlertBox({
              type: 'success',
              message: `Adres IP ${response.data.bannedIP} został zbanowany`,
              onConfirm: () => setAlertBox(null)
            });
            fetchUsers();
            fetchBannedIPs();
          } catch (error: any) {
            setAlertBox({
              type: 'error',
              message: error.response?.data?.error || 'Nie udało się zbanować adresu IP',
              onConfirm: () => setAlertBox(null)
            });
          }
        },
        onCancel: () => setAlertBox(null)
      });
    };

    const unbanIP = async (banId: string) => {
      try {
        await axios.post(`${API_BASE}/admin/unban-ip`, { banId }, {
          headers: { Authorization: `Bearer ${token}` },
        });
        fetchBannedIPs();
        setAlertBox({
          type: 'success',
          message: 'Adres IP został odbanowany',
          onConfirm: () => setAlertBox(null)
        });
      } catch (error) {
        setAlertBox({
          type: 'error',
          message: 'Nie udało się odbanować adresu IP',
          onConfirm: () => setAlertBox(null)
        });
      }
    };

    const fetchBannedIPs = async () => {
      setLoading(true);
      try {
        const res = await axios.get(`${API_BASE}/admin/banned-ips`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        setBannedIPs(res.data);
      } catch (error) {
        setAlertBox({
          type: 'error',
          message: 'Nie udało się pobrać listy zbanowanych IP',
          onConfirm: () => setAlertBox(null)
        });
      }
      setLoading(false);
    };

    const deleteEntry = async (id: string) => {
      try {
        await axios.delete(`${API_BASE}/admin/mood-entry/${id}`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        fetchEntries();
      } catch (error) {
        setAlertBox({
          type: 'error',
          message: 'Nie udało się usunąć wpisu',
          onConfirm: () => setAlertBox(null)
        });
      }
    };

    return (
      <div className={styles.adminPanel}>
        <h2 className={styles.adminTitle}>
          Panel Moderatora
        </h2>
        
        {helpRequests.length > 0 && (
          <div style={{marginBottom:'20px'}}>
            <h3 style={{fontSize:'18px',fontWeight:'700',marginBottom:'12px'}}>Prośby o pomoc:</h3>
            <div className={styles.requestsList}>
              {helpRequests.map((req) => (
                <div key={req.userId} className={styles.requestItem}>
                  <div className={styles.requestInfo}>
                    <span>👤</span>
                    <span>{req.nickname}</span>
                  </div>
                  <button
                    onClick={() => onConnect(req.userId)}
                    className={styles.connectButton}
                  >
                    Połącz
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}
        
        <div style={{display:'flex',gap:'12px',marginBottom:'24px',flexWrap:'wrap'}}>
          <button
            onClick={fetchUsers}
            className={styles.submitButton}
            style={{flex:'1',minWidth:'200px'}}
          >
            <span>👥</span> Pokaż użytkowników
          </button>
          <button
            onClick={fetchBannedIPs}
            className={styles.submitButton}
            style={{flex:'1',minWidth:'200px'}}
          >
            <span>🚫</span> Zbanowane IP
          </button>
        </div>

        {loading && (
          <div style={{display:'flex',justifyContent:'center',padding:'40px 0'}}>
            <div style={{fontSize:'20px',color:'#8e44ad',fontWeight:'600'}}>Ładowanie...</div>
          </div>
        )}

        {users.length > 0 && (
          <div style={{marginBottom:'24px'}}>
            <h3 style={{fontSize:'20px',fontWeight:'700',marginBottom:'16px',display:'flex',alignItems:'center',gap:'8px'}}>
              <span>👥</span> Lista użytkowników
            </h3>
            <div style={{display:'grid',gap:'12px'}}>
              {users.map((user) => (
                <div key={user.id} style={{background:'#f9fafb',border:'2px solid #e5e7eb',borderRadius:'14px',padding:'16px'}}>
                  <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',flexWrap:'wrap',gap:'12px'}}>
                    <div style={{display:'flex',alignItems:'center',gap:'12px'}}>
                      <div style={{fontSize:'24px'}}>👤</div>
                      <div>
                        <div style={{fontWeight:'700',color:'#111827'}}>{user.nickname}</div>
                        <div style={{fontSize:'13px',color:'#6b7280'}}>{user.email}</div>
                      </div>
                    </div>
                    <div style={{display:'flex',alignItems:'center',gap:'10px',flexWrap:'wrap'}}>
                      <span style={{
                        padding:'6px 12px',
                        borderRadius:'10px',
                        fontWeight:'600',
                        fontSize:'13px',
                        background: user.isBanned ? '#fee2e2' : '#d1fae5',
                        color: user.isBanned ? '#dc2626' : '#059669'
                      }}>
                        {user.isBanned ? 'Zbanowany' : 'Aktywny'}
                      </span>
                      {user.isAdmin && (
                        <span style={{
                          padding:'6px 12px',
                          borderRadius:'10px',
                          fontWeight:'600',
                          fontSize:'13px',
                          background: '#dbeafe',
                          color: '#1e40af'
                        }}>
                          ⚡ Moderator
                        </span>
                      )}
                      {!user.isAdmin && (
                        <>
                          <button
                            onClick={() => toggleBan(user.id, user.isBanned)}
                            style={{
                              padding:'8px 16px',
                              borderRadius:'10px',
                              fontWeight:'600',
                              border:'none',
                              cursor:'pointer',
                              background: user.isBanned ? 'linear-gradient(135deg,#10b981,#14b8a6)' : 'linear-gradient(135deg,#dc2626,#ef4444)',
                              color:'#fff',
                              transition:'all .2s'
                            }}
                          >
                            {user.isBanned ? '✅ Odbanuj' : '🚫 Zbanuj'}
                          </button>
                          <button
                            onClick={() => banIP(user.id)}
                            style={{
                              padding:'8px 16px',
                              borderRadius:'10px',
                              fontWeight:'600',
                              border:'none',
                              cursor:'pointer',
                              background: 'linear-gradient(135deg,#7c3aed,#a855f7)',
                              color:'#fff',
                              transition:'all .2s'
                            }}
                          >
                            🌐 Ban IP
                          </button>
                        </>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {entries.length > 0 && (
          <div>
            <h3 style={{fontSize:'20px',fontWeight:'700',marginBottom:'16px',display:'flex',alignItems:'center',gap:'8px'}}>
              <span>📋</span> Wszystkie wpisy
            </h3>
            <div style={{display:'grid',gap:'12px'}}>
              {entries.map((entry) => (
                <div key={entry.id} style={{background:'#f9fafb',border:'2px solid #e5e7eb',borderRadius:'14px',padding:'16px'}}>
                  <div style={{display:'flex',justifyContent:'space-between',alignItems:'start',marginBottom:'12px'}}>
                    <div style={{display:'flex',alignItems:'center',gap:'12px'}}>
                      <div style={{
                        width:'40px',
                        height:'40px',
                        borderRadius:'10px',
                        background:'linear-gradient(135deg,#8e44ad,#9b59b6)',
                        display:'flex',
                        alignItems:'center',
                        justifyContent:'center',
                        color:'#fff',
                        fontWeight:'700',
                        fontSize:'18px'
                      }}>
                        {entry.mood}
                      </div>
                      <div>
                        <div style={{fontWeight:'700',color:'#111827'}}>{entry.user?.nickname || 'Anonim'}</div>
                        <div style={{fontSize:'13px',color:'#6b7280'}}>
                          {new Date(entry.createdAt).toLocaleString('pl-PL', { 
                            day: 'numeric', 
                            month: 'short', 
                            year: 'numeric',
                            hour: '2-digit', 
                            minute: '2-digit' 
                          })}
                        </div>
                      </div>
                    </div>
                  </div>
                  <p style={{color:'#374151',background:'#fff',padding:'12px',borderRadius:'10px',marginBottom:'12px',lineHeight:'1.6'}}>
                    {entry.note || '💬 Brak notatki'}
                  </p>
                  <button
                    onClick={() => deleteEntry(entry.id)}
                    className={styles.deleteButton}
                  >
                    <span>🗑️</span> Usuń wpis
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}

        {bannedIPs.length > 0 && (
          <div style={{marginBottom:'24px'}}>
            <h3 style={{fontSize:'20px',fontWeight:'700',marginBottom:'16px',display:'flex',alignItems:'center',gap:'8px'}}>
              <span>🚫</span> Zbanowane adresy IP
            </h3>
            <div style={{display:'grid',gap:'12px'}}>
              {bannedIPs.map((ban) => (
                <div key={ban.id} style={{background:'#fef2f2',border:'2px solid #fecaca',borderRadius:'14px',padding:'16px'}}>
                  <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',flexWrap:'wrap',gap:'12px'}}>
                    <div style={{display:'flex',alignItems:'center',gap:'12px'}}>
                      <div style={{fontSize:'24px'}}>🌐</div>
                      <div>
                        <div style={{fontWeight:'700',color:'#991b1b'}}>🔒 Adres IP (ukryty)</div>
                        <div style={{fontSize:'13px',color:'#6b7280',marginTop:'4px'}}>
                          {ban.reason}
                        </div>
                        <div style={{fontSize:'12px',color:'#9ca3af',marginTop:'4px'}}>
                          Zbanowano: {new Date(ban.createdAt).toLocaleString('pl-PL', {
                            day: 'numeric',
                            month: 'short',
                            year: 'numeric',
                            hour: '2-digit',
                            minute: '2-digit'
                          })}
                        </div>
                      </div>
                    </div>
                    <button
                      onClick={() => unbanIP(ban.id)}
                      style={{
                        padding:'8px 16px',
                        borderRadius:'10px',
                        fontWeight:'600',
                        border:'none',
                        cursor:'pointer',
                        background: 'linear-gradient(135deg,#10b981,#14b8a6)',
                        color:'#fff',
                        transition:'all .2s'
                      }}
                    >
                      ✅ Odbanuj IP
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        <div className={styles.adminDropdownWrapper} ref={adminDropdownRef} style={{position:'relative'}}>
          <button
            onClick={() => setAdminDropdownOpen(!adminDropdownOpen)}
            className={`${styles.submitButton} ${helpRequests.length > 0 ? styles.adminButtonAlert : ''}`}
            aria-expanded={adminDropdownOpen}
            aria-haspopup="menu"
          >
            <span style={{fontSize:20}}>🆘</span>
            <span>Prośby o pomoc ({helpRequests.length})</span>
          </button>
          {adminDropdownOpen && (
            <div className={styles.adminDropdown} role="menu">
              {helpRequests.length === 0 ? (
                <div className={styles.adminDropdownEmpty}>
                  <div className={styles.emptyIcon}>✅</div>
                  <div className={styles.emptyText}>Brak oczekujących</div>
                </div>
              ) : (
                helpRequests.map((req) => (
                  <button
                    key={req.userId}
                    onClick={() => onConnect(req.userId)}
                    className={styles.adminDropdownItem}
                    role="menuitem"
                  >
                    <span className={styles.reqIcon}>💬</span>
                    <span>{req.nickname}</span>
                  </button>
                ))
              )}
            </div>
          )}
        </div>
      </div>
    );
  };

  if (isLoading) {
    return (
      <div className={styles.screen} style={{display:'flex',alignItems:'center',justifyContent:'center'}}>
        <div style={{fontSize:'20px',color:'#fff',fontWeight:'600'}}>Ładowanie...</div>
      </div>
    );
  }

  if (!token) {
    return null;
  }

  const renderDashboard = () => {
    const totalEntries = entries.length;
    const avgMood = totalEntries > 0 
      ? (entries.reduce((sum, e) => sum + e.mood, 0) / totalEntries).toFixed(1) 
      : '0';
    const todayEntries = entries.filter(e => {
      const entryDate = new Date(e.createdAt);
      const today = new Date();
      return entryDate.toDateString() === today.toDateString();
    }).length;

    const moodDistribution = [1, 2, 3, 4, 5].map(mood => ({
      mood,
      count: entries.filter(e => e.mood === mood).length,
      percentage: totalEntries > 0 ? (entries.filter(e => e.mood === mood).length / totalEntries * 100) : 0
    }));

    const last7Days = Array.from({ length: 7 }, (_, i) => {
      const date = new Date();
      date.setDate(date.getDate() - (6 - i));
      return date;
    });

    const weeklyData = last7Days.map(date => {
      const dayEntries = entries.filter(e => {
        const entryDate = new Date(e.createdAt);
        return entryDate.toDateString() === date.toDateString();
      });
      return {
        day: date.toLocaleDateString('pl-PL', { weekday: 'short' }),
        count: dayEntries.length,
        avgMood: dayEntries.length > 0 
          ? (dayEntries.reduce((sum, e) => sum + e.mood, 0) / dayEntries.length).toFixed(1)
          : 0
      };
    });

    const sortedEntries = [...entries].sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
    let currentStreak = 0;
    let checkDate = new Date();
    for (let i = 0; i < 365; i++) {
      const hasEntry = sortedEntries.some(e => {
        const entryDate = new Date(e.createdAt);
        return entryDate.toDateString() === checkDate.toDateString();
      });
      if (hasEntry) {
        currentStreak++;
        checkDate.setDate(checkDate.getDate() - 1);
      } else if (i === 0 && !hasEntry) {
        checkDate.setDate(checkDate.getDate() - 1);
      } else {
        break;
      }
    }

    const moodTrend = totalEntries >= 2 
      ? (() => {
          const halfPoint = Math.floor(totalEntries / 2);
          const recentEntries = entries.slice(0, Math.max(1, halfPoint));
          const olderEntries = entries.slice(Math.max(1, halfPoint));
          const recentAvg = recentEntries.reduce((s, e) => s + e.mood, 0) / recentEntries.length;
          const olderAvg = olderEntries.reduce((s, e) => s + e.mood, 0) / olderEntries.length;
          return recentAvg > olderAvg;
        })()
      : null;

    return (
      <div>
        <h2 style={{fontSize:'32px',fontWeight:'800',color:'#ffffffff',marginBottom:'32px',textAlign:'center'}}>
          📊 Dashboard Analityczny
        </h2>

        <div className={styles.dashboardGrid}>
          <div className={styles.summaryCard}>
            <div className={styles.summaryIcon}>📝</div>
            <div className={styles.summaryTitle}>Wszystkie wpisy</div>
            <div className={styles.summaryValue}>{totalEntries}</div>
            <div style={{fontSize:'12px',color:'#6b7280',marginTop:'8px'}}>
              Dzisiaj: {todayEntries}
            </div>
          </div>
          <div className={styles.summaryCard}>
            <div className={styles.summaryIcon}>😊</div>
            <div className={styles.summaryTitle}>Średni nastrój</div>
            <div className={styles.summaryValue}>{avgMood}/5</div>
            {moodTrend !== null && (
              <div style={{fontSize:'12px',color: moodTrend ? '#10b981' : '#ef4444',marginTop:'8px',fontWeight:'600'}}>
                {moodTrend ? '↗ Rosnący' : '↘ Malejący'}
              </div>
            )}
          </div>
          <div className={styles.summaryCard}>
            <div className={styles.summaryIcon}>🔥</div>
            <div className={styles.summaryTitle}>Seria dni wpisów dziennika</div>
            <div className={styles.summaryValue}>{currentStreak}</div>
            <div style={{fontSize:'12px',color:'#6b7280',marginTop:'8px'}}>
              dni z rzędu
            </div>
          </div>
          <div className={styles.summaryCard}>
            <div className={styles.summaryIcon}>👥</div>
            <div className={styles.summaryTitle}>Oczekujące prośby</div>
            <div className={styles.summaryValue}>{friendRequests.length}</div>
            <div style={{fontSize:'12px',color:'#6b7280',marginTop:'8px'}}>
              o dodanie znajomego
            </div>
          </div>
        </div>

        <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:'24px',marginBottom:'24px'}}>
          
          <div style={{background:'#fff',borderRadius:'22px',padding:'28px',boxShadow:'0 12px 40px rgba(0,0,0,0.12)'}}>
            <h3 style={{fontSize:'20px',fontWeight:'700',color:'#1f2937',marginBottom:'24px'}}>
              Ilość wpisów w ostatnim tygodniu
            </h3>
            <div style={{display:'flex',alignItems:'flex-end',justifyContent:'space-between',height:'200px',gap:'8px'}}>
              {weeklyData.map((day, i) => {
                const maxCount = Math.max(...weeklyData.map(d => d.count), 1);
                const height = (day.count / maxCount) * 100;
                return (
                  <div key={i} style={{flex:1,display:'flex',flexDirection:'column',alignItems:'center',gap:'8px'}}>
                    <div style={{
                      width:'100%',
                      height:`${height}%`,
                      background:'linear-gradient(180deg, #667eea 0%, #764ba2 100%)',
                      borderRadius:'8px 8px 0 0',
                      position:'relative',
                      minHeight:'8px',
                      display:'flex',
                      alignItems:'center',
                      justifyContent:'center',
                      color:'#fff',
                      fontSize:'12px',
                      fontWeight:'700'
                    }}>
                      {day.count > 0 && day.count}
                    </div>
                    <div style={{fontSize:'12px',fontWeight:'600',color:'#6b7280'}}>{day.day}</div>
                  </div>
                );
              })}
            </div>
          </div>

          <div style={{background:'#fff',borderRadius:'22px',padding:'28px',boxShadow:'0 12px 40px rgba(0,0,0,0.12)'}}>
            <h3 style={{fontSize:'20px',fontWeight:'700',color:'#1f2937',marginBottom:'24px'}}>
              Rozkład nastrojów
            </h3>
            <div style={{display:'flex',flexDirection:'column',gap:'16px'}}>
              {moodDistribution.reverse().map((item, i) => {
                const colors = ['#ef4444', '#f97316', '#eab308', '#84cc16', '#10b981'];
                const emojis = ['😢', '😕', '😐', '🙂', '😊'];
                return (
                  <div key={item.mood} style={{display:'flex',alignItems:'center',gap:'12px'}}>
                    <div style={{fontSize:'24px',width:'32px'}}>{emojis[item.mood - 1]}</div>
                    <div style={{fontSize:'14px',fontWeight:'700',color:'#1f2937',width:'20px'}}>{item.mood}</div>
                    <div style={{flex:1,background:'#f3f4f6',borderRadius:'999px',height:'24px',position:'relative',overflow:'hidden'}}>
                      <div style={{
                        width:`${item.percentage}%`,
                        height:'100%',
                        background:colors[item.mood - 1],
                        borderRadius:'999px',
                        transition:'width 0.5s ease'
                      }}/>
                    </div>
                    <div style={{fontSize:'14px',fontWeight:'600',color:'#6b7280',minWidth:'60px',textAlign:'right'}}>
                      {item.count} ({item.percentage.toFixed(0)}%)
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        <div style={{marginBottom:'24px'}}>
          <div style={{background:'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',borderRadius:'22px',padding:'32px',boxShadow:'0 12px 40px rgba(0,0,0,0.12)',textAlign:'center',color:'#fff',display:'flex',flexDirection:'column',justifyContent:'center'}}>
            <div style={{fontSize:'48px',marginBottom:'16px'}}>🌟</div>
            <h3 style={{fontSize:'24px',fontWeight:'700',marginBottom:'12px'}}>
              Witaj, {getUsername()}!
            </h3>
            <p style={{fontSize:'14px',lineHeight:'1.6',opacity:0.95}}>
              {currentStreak > 0 ? `Masz ${currentStreak} dni serii!` : 'Rozpocznij serię!'}
              <br/>
              {totalEntries > 0 && ` Średnia nastroju: ${avgMood}/5`}
            </p>
          </div>
        </div>
      </div>
    );
  };

  const renderAIChatView = () => (
    <div>
      <div style={{background:'#fff',borderRadius:'22px',padding:'32px',boxShadow:'0 12px 40px rgba(0,0,0,0.12)'}}>
        <AIChat token={token!} isOpen={true} inline={true} onClose={() => setCurrentView('dashboard')} />
      </div>
    </div>
  );

  const renderModChatView = () => (
    <div>
      <div style={{background:'#fff',borderRadius:'22px',padding:'32px',boxShadow:'0 12px 40px rgba(0,0,0,0.12)'}}>
        <h2 style={{fontSize:'28px',fontWeight:'800',color:'#1f2937',marginBottom:'24px'}}>
          💬 Chat z Moderatorem
        </h2>
        
        {!privateChat.active && !helpRequested && (
          <div style={{textAlign:'center',padding:'60px 20px'}}>
            <div style={{fontSize:'64px',marginBottom:'24px'}}>💬</div>
            <h3 style={{fontSize:'24px',fontWeight:'700',color:'#1f2937',marginBottom:'16px'}}>
              Potrzebujesz wsparcia?
            </h3>
            <p style={{fontSize:'16px',color:'#6b7280',marginBottom:'32px',lineHeight:'1.6'}}>
              Kliknij poniższy przycisk, aby wysłać prośbę o pomoc do moderatora. <br/>
              Gdy moderator się połączy, będziecie mogli rozmawiać w czasie rzeczywistym.
            </p>
            <button
              onClick={() => requestHelp()}
              style={{
                background:'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
                color:'#fff',
                border:'none',
                padding:'16px 32px',
                borderRadius:'12px',
                fontSize:'16px',
                fontWeight:'700',
                cursor:'pointer',
                boxShadow:'0 4px 12px rgba(102, 126, 234, 0.4)',
                transition:'all 0.3s'
              }}
              onMouseEnter={(e) => e.currentTarget.style.transform = 'scale(1.05)'}
              onMouseLeave={(e) => e.currentTarget.style.transform = 'scale(1)'}
            >
              Wyślij prośbę o pomoc
            </button>
          </div>
        )}

        {helpRequested && !privateChat.active && (
          <div style={{textAlign:'center',padding:'60px 20px'}}>
            <div style={{fontSize:'64px',marginBottom:'24px'}}>⏳</div>
            <h3 style={{fontSize:'24px',fontWeight:'700',color:'#1f2937',marginBottom:'16px'}}>
              Oczekiwanie na moderatora...
            </h3>
            <p style={{fontSize:'16px',color:'#6b7280'}}>
              Twoja prośba została wysłana. Moderator wkrótce się z Tobą połączy.
            </p>
          </div>
        )}

        {privateChat.active && (
          <div>
            <div style={{background:'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',borderRadius:'16px',padding:'20px',marginBottom:'24px',color:'#fff'}}>
              <div style={{display:'flex',alignItems:'center',justifyContent:'space-between'}}>
                <div style={{display:'flex',alignItems:'center',gap:'12px'}}>
                  <div style={{width:'48px',height:'48px',borderRadius:'50%',background:'rgba(255,255,255,0.2)',display:'flex',alignItems:'center',justifyContent:'center',fontSize:'24px'}}>
                    👤
                  </div>
                  <div>
                    <div style={{fontSize:'18px',fontWeight:'700'}}>Prywatna rozmowa</div>
                    <div style={{fontSize:'14px',opacity:0.9}}>{privateChat.nickname ? `z ${privateChat.nickname}` : 'Wsparcie'}</div>
                  </div>
                </div>
                <button
                  onClick={() => {
                    if (socket) {
                      socket.emit('leaveChat', {});
                    }
                    setPrivateChat({ active: false });
                    setMessages([]);
                    setCurrentView('dashboard');
                  }}
                  style={{
                    background:'rgba(255,255,255,0.2)',
                    border:'none',
                    color:'#fff',
                    padding:'10px 20px',
                    borderRadius:'8px',
                    fontSize:'14px',
                    fontWeight:'600',
                    cursor:'pointer',
                    transition:'all 0.3s'
                  }}
                  onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(255,255,255,0.3)'}
                  onMouseLeave={(e) => e.currentTarget.style.background = 'rgba(255,255,255,0.2)'}
                >
                  ❌ Zakończ
                </button>
              </div>
            </div>

            <div style={{background:'#f9fafb',borderRadius:'16px',padding:'24px',minHeight:'400px',maxHeight:'500px',overflowY:'auto',marginBottom:'20px'}}>
              {messages.length === 0 ? (
                <div style={{textAlign:'center',padding:'40px 0',color:'#9ca3af'}}>
                  <div style={{fontSize:'48px',marginBottom:'8px'}}>💭</div>
                  <div style={{fontSize:'14px'}}>Napisz pierwszą wiadomość</div>
                </div>
              ) : (
                <div style={{display:'flex',flexDirection:'column',gap:'12px'}}>
                  {messages.map((m, i) => (
                    <div key={i} style={{display:'flex',justifyContent: m.sender === 'Ja' ? 'flex-end' : 'flex-start'}}>
                      <div style={{
                        maxWidth:'70%',
                        padding:'12px 16px',
                        borderRadius:'16px',
                        background: m.sender === 'Ja' 
                          ? 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)' 
                          : '#fff',
                        color: m.sender === 'Ja' ? '#fff' : '#1f2937',
                        boxShadow: m.sender === 'Ja' ? 'none' : '0 2px 8px rgba(0,0,0,0.1)'
                      }}>
                        <div style={{fontSize:'12px',fontWeight:'600',marginBottom:'4px',opacity:0.8}}>
                          {m.sender} • {new Date(m.timestamp).toLocaleTimeString('pl-PL', { hour: '2-digit', minute: '2-digit' })}
                        </div>
                        <div style={{fontSize:'14px',lineHeight:'1.5'}}>{m.message}</div>
                      </div>
                    </div>
                  ))}
                  <div ref={messagesEndRef} />
                </div>
              )}
            </div>

            <div style={{display:'flex',gap:'12px'}}>
              <input
                value={newMessage}
                onChange={(e) => setNewMessage(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); } }}
                placeholder="Wpisz wiadomość..."
                style={{
                  flex:1,
                  padding:'14px 20px',
                  borderRadius:'12px',
                  border:'2px solid #e5e7eb',
                  fontSize:'15px',
                  outline:'none',
                  transition:'border 0.3s'
                }}
                onFocus={(e) => e.currentTarget.style.borderColor = '#667eea'}
                onBlur={(e) => e.currentTarget.style.borderColor = '#e5e7eb'}
              />
              <button 
                onClick={sendMessage}
                style={{
                  background:'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
                  color:'#fff',
                  border:'none',
                  padding:'14px 28px',
                  borderRadius:'12px',
                  fontSize:'15px',
                  fontWeight:'700',
                  cursor:'pointer',
                  transition:'all 0.3s'
                }}
                onMouseEnter={(e) => e.currentTarget.style.transform = 'scale(1.05)'}
                onMouseLeave={(e) => e.currentTarget.style.transform = 'scale(1)'}
              >
                Wyślij
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );

  const renderSettingsView = () => (
    <div>
      <div style={{background:'#fff',borderRadius:'22px',padding:'32px',boxShadow:'0 12px 40px rgba(0,0,0,0.12)',marginBottom:'24px'}}>
        <h2 style={{fontSize:'28px',fontWeight:'800',color:'#1f2937',marginBottom:'24px'}}>
          ⚙️ Ustawienia
        </h2>

        <div style={{borderTop:'1px solid #e5e7eb',paddingTop:'24px',marginTop:'24px'}}>
          <h3 style={{fontSize:'20px',fontWeight:'700',color:'#1f2937',marginBottom:'16px'}}>
            🔐 Weryfikacja dwuetapowa (2FA)
          </h3>
          <p style={{color:'#6b7280',marginBottom:'24px',lineHeight:'1.6'}}>
            Zabezpiecz swoje konto dodatkową warstwą ochrony. Użyj aplikacji Authy, Google Authenticator lub innej aplikacji TOTP.
          </p>

          {!twoFactorEnabled && !twoFactorSetupActive && (
            <button
              onClick={setup2FA}
              style={{
                background:'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
                color:'#fff',
                padding:'14px 28px',
                borderRadius:'12px',
                border:'none',
                fontSize:'16px',
                fontWeight:'600',
                cursor:'pointer',
                boxShadow:'0 4px 12px rgba(102,126,234,0.4)',
                transition:'all 0.3s'
              }}
            >
              Włącz weryfikację dwuetapową
            </button>
          )}

          {twoFactorSetupActive && (
            <div style={{background:'#f9fafb',borderRadius:'16px',padding:'24px'}}>
              <h4 style={{fontSize:'18px',fontWeight:'600',color:'#1f2937',marginBottom:'16px'}}>
                Konfiguracja 2FA
              </h4>
              
              <div style={{marginBottom:'24px'}}>
                <p style={{color:'#6b7280',marginBottom:'16px',fontSize:'15px'}}>
                  1. Zeskanuj kod QR w aplikacji Authy lub Google Authenticator
                </p>
                {twoFactorQR && (
                  <div style={{textAlign:'center',marginBottom:'16px'}}>
                    <img src={twoFactorQR} alt="QR Code" style={{maxWidth:'250px',border:'2px solid #e5e7eb',borderRadius:'12px',padding:'16px',background:'#fff'}} />
                  </div>
                )}
              </div>

              <div style={{marginBottom:'16px'}}>
                <p style={{color:'#6b7280',marginBottom:'8px',fontSize:'15px'}}>
                  Lub wprowadź klucz ręcznie:
                </p>
                <div style={{
                  background:'#fff',
                  padding:'12px 16px',
                  borderRadius:'8px',
                  border:'1px solid #e5e7eb',
                  fontFamily:'monospace',
                  fontSize:'14px',
                  color:'#1f2937',
                  wordBreak:'break-all'
                }}>
                  {twoFactorSecret}
                </div>
              </div>

              <div style={{marginBottom:'16px'}}>
                <p style={{color:'#6b7280',marginBottom:'8px',fontSize:'15px'}}>
                  2. Wprowadź 6-cyfrowy kod z aplikacji, aby zweryfikować konfigurację:
                </p>
                <input
                  type="text"
                  value={twoFactorCode}
                  onChange={(e) => setTwoFactorCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  placeholder="000000"
                  maxLength={6}
                  style={{
                    width:'100%',
                    padding:'14px 18px',
                    borderRadius:'12px',
                    border:'1px solid #d1d5db',
                    fontSize:'18px',
                    fontFamily:'monospace',
                    textAlign:'center',
                    letterSpacing:'8px'
                  }}
                />
              </div>

              <div style={{display:'flex',gap:'12px'}}>
                <button
                  onClick={enable2FA}
                  disabled={twoFactorCode.length !== 6}
                  style={{
                    flex:1,
                    background: twoFactorCode.length === 6 ? 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)' : '#e5e7eb',
                    color: twoFactorCode.length === 6 ? '#fff' : '#9ca3af',
                    padding:'14px 28px',
                    borderRadius:'12px',
                    border:'none',
                    fontSize:'16px',
                    fontWeight:'600',
                    cursor: twoFactorCode.length === 6 ? 'pointer' : 'not-allowed',
                    transition:'all 0.3s'
                  }}
                >
                  Weryfikuj i włącz
                </button>
                <button
                  onClick={() => {
                    setTwoFactorSetupActive(false);
                    setTwoFactorQR('');
                    setTwoFactorSecret('');
                    setTwoFactorCode('');
                  }}
                  style={{
                    background:'#fff',
                    color:'#6b7280',
                    padding:'14px 28px',
                    borderRadius:'12px',
                    border:'1px solid #d1d5db',
                    fontSize:'16px',
                    fontWeight:'600',
                    cursor:'pointer',
                    transition:'all 0.3s'
                  }}
                >
                  Anuluj
                </button>
              </div>
            </div>
          )}

          {twoFactorEnabled && !twoFactorSetupActive && (
            <div style={{background:'#f0fdf4',borderRadius:'16px',padding:'24px',border:'1px solid #86efac'}}>
              <div style={{display:'flex',alignItems:'center',gap:'12px',marginBottom:'16px'}}>
                <span style={{fontSize:'32px'}}>✅</span>
                <div>
                  <h4 style={{fontSize:'18px',fontWeight:'600',color:'#15803d',marginBottom:'4px'}}>
                    Weryfikacja dwuetapowa jest włączona
                  </h4>
                  <p style={{color:'#16a34a',fontSize:'14px'}}>
                    Twoje konto jest chronione dodatkową warstwą bezpieczeństwa
                  </p>
                </div>
              </div>
              <button
                onClick={disable2FA}
                style={{
                  background:'#fff',
                  color:'#dc2626',
                  padding:'12px 24px',
                  borderRadius:'12px',
                  border:'1px solid #fca5a5',
                  fontSize:'15px',
                  fontWeight:'600',
                  cursor:'pointer',
                  transition:'all 0.3s'
                }}
              >
                Wyłącz weryfikację dwuetapową
              </button>
            </div>
          )}
        </div>

        <div style={{borderTop:'1px solid #e5e7eb',paddingTop:'24px',marginTop:'24px'}}>
          <h3 style={{fontSize:'20px',fontWeight:'700',color:'#dc2626',marginBottom:'16px'}}>
            🗑️ Strefa niebezpieczna
          </h3>
          <p style={{color:'#6b7280',marginBottom:'24px',lineHeight:'1.6'}}>
            Usuń swoje konto i wszystkie powiązane dane. Ta operacja jest nieodwracalna.
          </p>
          
          <div style={{background:'#fef2f2',borderRadius:'16px',padding:'24px',border:'1px solid #fca5a5'}}>
            <h4 style={{fontSize:'16px',fontWeight:'600',color:'#991b1b',marginBottom:'8px'}}>
              Usuń konto na stałe
            </h4>
            <p style={{color:'#7f1d1d',fontSize:'14px',marginBottom:'16px',lineHeight:'1.5'}}>
              Po usunięciu konta wszystkie Twoje wpisy nastroju, rozmowy, dane i ustawienia zostaną trwale usunięte. 
              {twoFactorEnabled && ' Będziesz musiał podać kod 2FA, aby potwierdzić usunięcie.'}
            </p>
            <button
              onClick={deleteAccount}
              style={{
                background:'#dc2626',
                color:'#fff',
                padding:'12px 24px',
                borderRadius:'12px',
                border:'none',
                fontSize:'15px',
                fontWeight:'600',
                cursor:'pointer',
                transition:'all 0.3s',
                boxShadow:'0 2px 8px rgba(220, 38, 38, 0.3)'
              }}
              onMouseOver={(e) => e.currentTarget.style.background = '#b91c1c'}
              onMouseOut={(e) => e.currentTarget.style.background = '#dc2626'}
            >
              Usuń moje konto i dane
            </button>
          </div>
        </div>
      </div>
    </div>
  );

  const renderFriendsView = () => (
    <div>
      <div style={{background:'#fff',borderRadius:'22px',padding:'32px',boxShadow:'0 12px 40px rgba(0,0,0,0.12)'}}>
        <h2 style={{fontSize:'28px',fontWeight:'800',color:'#1f2937',marginBottom:'24px'}}>
          👥 Znajomi
        </h2>

        <div style={{background:'linear-gradient(135deg, #f093fb 0%, #f5576c 100%)',borderRadius:'16px',padding:'24px',marginBottom:'32px'}}>
          <h3 style={{fontSize:'18px',fontWeight:'700',color:'#fff',marginBottom:'16px'}}>Dodaj znajomego</h3>
          <div style={{display:'flex',gap:'12px'}}>
            <input
              type="text"
              value={friendUsername}
              onChange={(e) => setFriendUsername(e.target.value)}
              placeholder="Wpisz nazwę użytkownika..."
              onKeyDown={(e) => e.key === 'Enter' && sendFriendRequest()}
              style={{
                flex: 1,
                padding:'14px 18px',
                borderRadius:'12px',
                border:'none',
                fontSize:'15px',
                background:'rgba(255,255,255,0.95)'
              }}
            />
            <button
              onClick={sendFriendRequest}
              style={{
                background:'rgba(255,255,255,0.2)',
                color:'#fff',
                border:'2px solid rgba(255,255,255,0.4)',
                padding:'14px 28px',
                borderRadius:'12px',
                fontSize:'15px',
                fontWeight:'700',
                cursor:'pointer',
                transition:'all 0.3s'
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.background = 'rgba(255,255,255,0.3)';
                e.currentTarget.style.transform = 'scale(1.05)';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.background = 'rgba(255,255,255,0.2)';
                e.currentTarget.style.transform = 'scale(1)';
              }}
            >
              Wyślij zaproszenie
            </button>
          </div>
        </div>

        {friendRequests.length > 0 && (
          <div style={{marginBottom:'32px'}}>
            <h3 style={{fontSize:'20px',fontWeight:'700',color:'#1f2937',marginBottom:'16px'}}>
              📬 Zaproszenia ({friendRequests.length})
            </h3>
            <div style={{display:'flex',flexDirection:'column',gap:'12px'}}>
              {friendRequests.map((req) => (
                <div key={req.id} style={{
                  background:'#f9fafb',
                  borderRadius:'12px',
                  padding:'16px 20px',
                  display:'flex',
                  alignItems:'center',
                  justifyContent:'space-between'
                }}>
                  <div>
                    <div style={{fontSize:'16px',fontWeight:'600',color:'#1f2937'}}>{req.sender.nickname}</div>
                    <div style={{fontSize:'13px',color:'#6b7280'}}>chce dodać Cię do znajomych</div>
                  </div>
                  <div style={{display:'flex',gap:'8px'}}>
                    <button
                      onClick={() => acceptFriendRequest(req.id)}
                      style={{
                        background:'linear-gradient(135deg, #10b981 0%, #059669 100%)',
                        color:'#fff',
                        border:'none',
                        padding:'8px 16px',
                        borderRadius:'8px',
                        fontSize:'14px',
                        fontWeight:'600',
                        cursor:'pointer'
                      }}
                    >
                      ✓ Zaakceptuj
                    </button>
                    <button
                      onClick={() => rejectFriendRequest(req.id)}
                      style={{
                        background:'#e5e7eb',
                        color:'#6b7280',
                        border:'none',
                        padding:'8px 16px',
                        borderRadius:'8px',
                        fontSize:'14px',
                        fontWeight:'600',
                        cursor:'pointer'
                      }}
                    >
                      ✗ Odrzuć
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        <div style={{display:'grid',gridTemplateColumns: selectedFriend ? '320px 1fr' : '1fr',gap:'24px'}}>
          <div>
            <h3 style={{fontSize:'20px',fontWeight:'700',color:'#1f2937',marginBottom:'16px'}}>
              Twoi znajomi ({friends.length})
            </h3>
            <div style={{display:'flex',flexDirection:'column',gap:'10px'}}>
              {friends.length === 0 ? (
                <div style={{textAlign:'center',padding:'40px 20px',color:'#9ca3af'}}>
                  <div style={{fontSize:'48px',marginBottom:'12px'}}>👥</div>
                  <div style={{fontSize:'14px'}}>Nie masz jeszcze znajomych</div>
                  <div style={{fontSize:'13px',marginTop:'4px'}}>Dodaj kogoś, aby zacząć!</div>
                </div>
              ) : (
                friends.map((friend) => (
                  <div
                    key={friend.id}
                    onClick={() => setSelectedFriend(friend)}
                    style={{
                      background: selectedFriend?.id === friend.id 
                        ? 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)'
                        : '#f9fafb',
                      color: selectedFriend?.id === friend.id ? '#fff' : '#1f2937',
                      borderRadius:'12px',
                      padding:'16px',
                      cursor:'pointer',
                      transition:'all 0.3s',
                      border: selectedFriend?.id === friend.id ? 'none' : '2px solid transparent'
                    }}
                    onMouseEnter={(e) => {
                      if (selectedFriend?.id !== friend.id) {
                        e.currentTarget.style.background = '#e5e7eb';
                        e.currentTarget.style.borderColor = '#667eea';
                      }
                    }}
                    onMouseLeave={(e) => {
                      if (selectedFriend?.id !== friend.id) {
                        e.currentTarget.style.background = '#f9fafb';
                        e.currentTarget.style.borderColor = 'transparent';
                      }
                    }}
                  >
                    <div style={{fontSize:'16px',fontWeight:'700',marginBottom:'4px'}}>
                      {friend.nickname}
                    </div>
                    <div style={{fontSize:'12px',opacity:0.8}}>
                      Znajomi od {new Date(friend.friendsSince).toLocaleDateString('pl-PL')}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          {selectedFriend && (
            <div>
              <div style={{
                background:'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
                borderRadius:'16px',
                padding:'20px',
                marginBottom:'20px',
                color:'#fff'
              }}>
                <div style={{display:'flex',justifyContent:'space-between',alignItems:'center'}}>
                  <div>
                    <h3 style={{fontSize:'22px',fontWeight:'800',marginBottom:'8px'}}>
                      {selectedFriend.nickname}
                    </h3>
                    {friendStats && (
                      <div style={{display:'flex',gap:'24px',fontSize:'14px',opacity:0.95}}>
                        <div>📊 Średni nastrój: <strong>{friendStats.averageMood}</strong></div>
                        <div>🔥 Seria: <strong>{friendStats.currentStreak} dni</strong></div>
                        <div>📝 Wpisy: <strong>{friendStats.totalEntries}</strong></div>
                      </div>
                    )}
                  </div>
                  <button
                    onClick={() => removeFriend(selectedFriend.id)}
                    style={{
                      background:'rgba(255,255,255,0.2)',
                      color:'#fff',
                      border:'none',
                      padding:'10px 16px',
                      borderRadius:'8px',
                      fontSize:'13px',
                      fontWeight:'600',
                      cursor:'pointer'
                    }}
                  >
                    🗑️ Usuń znajomego
                  </button>
                </div>
              </div>

              <div style={{
                background:'#f9fafb',
                borderRadius:'16px',
                padding:'20px',
                minHeight:'400px',
                maxHeight:'500px',
                overflowY:'auto',
                marginBottom:'16px'
              }}>
                {friendMessages.length === 0 ? (
                  <div style={{textAlign:'center',padding:'40px 0',color:'#9ca3af'}}>
                    <div style={{fontSize:'48px',marginBottom:'8px'}}>💬</div>
                    <div style={{fontSize:'14px'}}>Nie masz jeszcze wiadomości</div>
                    <div style={{fontSize:'13px',marginTop:'4px'}}>Napisz coś poniżej!</div>
                  </div>
                ) : (
                  <div style={{display:'flex',flexDirection:'column',gap:'12px'}}>
                    {friendMessages.map((msg) => {
                      const isMyMessage = msg.sender.id !== selectedFriend.id;
                      return (
                        <div key={msg.id} style={{display:'flex',justifyContent: isMyMessage ? 'flex-end' : 'flex-start'}}>
                          <div style={{
                            maxWidth:'70%',
                            padding:'12px 16px',
                            borderRadius:'16px',
                            background: isMyMessage 
                              ? 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)' 
                              : '#fff',
                            color: isMyMessage ? '#fff' : '#1f2937',
                            boxShadow: isMyMessage ? 'none' : '0 2px 8px rgba(0,0,0,0.08)'
                          }}>
                            <div style={{fontSize:'14px',lineHeight:'1.5',wordWrap:'break-word'}}>
                              {msg.content}
                            </div>
                            <div style={{
                              fontSize:'11px',
                              marginTop:'4px',
                              opacity:0.7
                            }}>
                              {new Date(msg.createdAt).toLocaleTimeString('pl-PL', {hour:'2-digit',minute:'2-digit'})}
                            </div>
                          </div>
                        </div>
                      );
                    })}
                    <div ref={friendMessagesEndRef} />
                  </div>
                )}
              </div>

              <div style={{display:'flex',gap:'12px'}}>
                <input
                  type="text"
                  value={newFriendMessage}
                  onChange={(e) => setNewFriendMessage(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && sendFriendMessage()}
                  placeholder="Napisz wiadomość..."
                  style={{
                    flex:1,
                    padding:'14px 18px',
                    borderRadius:'12px',
                    border:'2px solid #e5e7eb',
                    fontSize:'15px',
                    transition:'all 0.3s'
                  }}
                  onFocus={(e) => e.currentTarget.style.borderColor = '#667eea'}
                  onBlur={(e) => e.currentTarget.style.borderColor = '#e5e7eb'}
                />
                <button
                  onClick={sendFriendMessage}
                  style={{
                    background:'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
                    color:'#fff',
                    border:'none',
                    padding:'14px 28px',
                    borderRadius:'12px',
                    fontSize:'15px',
                    fontWeight:'700',
                    cursor:'pointer',
                    transition:'all 0.3s'
                  }}
                  onMouseEnter={(e) => e.currentTarget.style.transform = 'scale(1.05)'}
                  onMouseLeave={(e) => e.currentTarget.style.transform = 'scale(1)'}
                >
                  Wyślij
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );

  const renderAdminView = () => (
    <AdminPanel 
      token={token!} 
      helpRequests={helpRequests} 
      onConnect={connectToUser}
    />
  );

  const renderDiaryView = () => (
    <div>
      <div className={styles.card} style={{marginBottom:'24px'}}>
        <h2 className={styles.cardTitle}>
          Dzienniczek Emocjonalny
        </h2>
        <form onSubmit={handleSaveMood} className={styles.form}>
                <div>
                  <label className={styles.moodLabel}>
                    Nastrój: <span className={styles.moodValue}>{mood}/5</span>
                  </label>
                  <div className={styles.moodButtons}>
                    {[
                      { value: 1, emoji: '1' },
                      { value: 2, emoji: '2' },
                      { value: 3, emoji: '3' },
                      { value: 4, emoji: '4' },
                      { value: 5, emoji: '5' },
                    ].map(({ value, emoji }) => (
                      <button
                        key={value}
                        type="button"
                        onClick={() => setMood(value)}
                        className={`${styles.moodButton} ${mood === value ? styles.active : ''}`}
                      >
                        {emoji}
                      </button>
                    ))}
                  </div>
                </div>
                <div className={styles.textareaWrapper}>
                  <textarea
                    placeholder="Podziel się swoimi myślami i emocjami..."
                    value={note}
                    onChange={(e) => setNote(e.target.value)}
                    className={styles.textarea}
                  />
                </div>
                <button
                  type="submit"
                  className={styles.submitButton}
                >
                  Zapisz nastrój
                </button>
        </form>
      </div>

      <div className={styles.card}>
        <div className={styles.historyHeader}>
          <h2 className={styles.cardTitle}>
            Historia nastrojów
          </h2>
          <button
            onClick={() => setShowAllEntriesModal(true)}
            className={styles.refreshButton}
          >
            Zobacz wszystko
          </button>
        </div>
        <div className={styles.entriesList}>
          {entries.length === 0 ? (
            <div className={styles.emptyState}>
              <div className={styles.emptyIcon}>📭</div>
              <p>Brak wpisów. Zacznij zapisywać swoje nastroje!</p>
            </div>
          ) : (
            entries.map((e) => {
              return (
                <div key={e.id} className={styles.entry}>
                  <div className={styles.entryHeader}>
                    <div className={styles.moodBadge}>
                      <span>{e.mood}/5</span>
                    </div>
                    <span className={styles.entryDate}>
                      🕐 {new Date(e.createdAt).toLocaleString('pl-PL', { 
                        day: 'numeric', 
                        month: 'short', 
                        hour: '2-digit', 
                        minute: '2-digit' 
                      })}
                    </span>
                  </div>
                  <p className={styles.entryNote}>
                    {e.note || ' Brak notatki'}
                  </p>
                  <button
                    onClick={() => handleDeleteMood(e.id)}
                    className={styles.deleteButton}
                  >
                    Usuń
                  </button>
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );

  if (isLoading) {
    return (
      <div className={styles.screen} style={{display:'flex',alignItems:'center',justifyContent:'center',minHeight:'100vh'}}>
        <div style={{textAlign:'center'}}>
          <div style={{fontSize:48,marginBottom:16}}>⏳</div>
          <div style={{fontSize:20,fontWeight:700,color:'#111827'}}>Ładowanie...</div>
        </div>
      </div>
    );
  }


  return (
    <div className={styles.screen}>
      <button 
        onClick={() => setSidebarOpen(!sidebarOpen)}
        className={styles.menuToggle}
        aria-label="Toggle menu"
      >
        {sidebarOpen ? '✕' : '☰'}
      </button>

      <div 
        className={`${styles.sidebarOverlay} ${sidebarOpen ? styles.visible : ''}`}
        onClick={() => setSidebarOpen(false)}
      />

      <div className={`${styles.sidebar} ${sidebarOpen ? styles.open : ''}`}>
        <div className={styles.sidebarHeader}>
          <h2 className={styles.sidebarBrand}>🧠 HelpForMind</h2>
        </div>
        <nav className={styles.sidebarNav}>
          <button 
            onClick={() => { setCurrentView('dashboard'); setSidebarOpen(false); }}
            className={`${styles.navItem} ${currentView === 'dashboard' ? styles.active : ''}`}
          >
            📊 Podsumowanie
          </button>
          <button 
            onClick={() => { setCurrentView('diary'); setSidebarOpen(false); }}
            className={`${styles.navItem} ${currentView === 'diary' ? styles.active : ''}`}
          >
            📖 Dziennik emocjonalny
          </button>
          <button 
            onClick={() => { setCurrentView('ai-chat'); setSidebarOpen(false); }}
            className={`${styles.navItem} ${currentView === 'ai-chat' ? styles.active : ''}`}
          >
            🤖 AI Chat
          </button>
          <button 
            onClick={() => { setCurrentView('mod-chat'); setSidebarOpen(false); }}
            className={`${styles.navItem} ${currentView === 'mod-chat' ? styles.active : ''}`}
          >
            💬 Chat z moderatorem
          </button>
          <button 
            onClick={() => { setCurrentView('friends'); setSidebarOpen(false); }}
            className={`${styles.navItem} ${currentView === 'friends' ? styles.active : ''}`}
          >
            👥 Znajomi
          </button>
          {isAdmin && (
            <button 
              onClick={() => { setCurrentView('admin'); setSidebarOpen(false); }}
              className={`${styles.navItem} ${currentView === 'admin' ? styles.active : ''}`}
            >
              🛡️ Panel admina
            </button>
          )}
        </nav>
        <div style={{marginTop: 'auto', paddingTop: '24px', borderTop: '2px solid rgba(255, 255, 255, 0.2)', position: 'relative'}}>
          <button 
            onClick={() => setSidebarProfileOpen(!sidebarProfileOpen)}
            className={`${styles.navItem} ${sidebarProfileOpen ? styles.active : ''}`}
          >
            <span style={{flex: 1}}>👤 Profil - {getUsername()}</span>
            <span style={{fontSize: '14px', transition: 'transform 0.3s', transform: sidebarProfileOpen ? 'rotate(180deg)' : 'rotate(0deg)'}}>▼</span>
          </button>
        </div>
      </div>

      {sidebarProfileOpen && sidebarOpen && (
        <div className={styles.profileSubmenu}>
          <button 
            onClick={() => { setCurrentView('settings'); setSidebarOpen(false); }}
            style={{
              width: '100%',
              background: 'none',
              border: 'none',
              color: '#667eea',
              padding: '16px 20px',
              borderRadius: '12px',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '12px',
              fontSize: '16px',
              fontWeight: 600,
              transition: 'all 0.3s',
              marginBottom: '8px',
            }}
            onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(102, 126, 234, 0.1)'}
            onMouseLeave={(e) => e.currentTarget.style.background = 'none'}
          >
            Ustawienia
          </button>
          <button 
            onClick={() => { handleLogout(); setSidebarOpen(false); }}
            style={{
              width: '100%',
              background: 'none',
              border: 'none',
              color: '#ef4444',
              padding: '16px 20px',
              borderRadius: '12px',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '12px',
              fontSize: '16px',
              fontWeight: 600,
              transition: 'all 0.3s',
            }}
            onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(239, 68, 68, 0.1)'}
            onMouseLeave={(e) => e.currentTarget.style.background = 'none'}
          >
            Wyloguj się
          </button>
        </div>
      )}

      <div className={styles.container}>
        <header className={styles.header}>
          <h1 className={styles.brand}>🧠 HelpForMind</h1>
          <p className={styles.subtitle}>Twoja przestrzeń do dbania o zdrowie psychiczne</p>
        </header>

        <div className={styles.diaryCenter}>
          {currentView === 'dashboard' && renderDashboard()}
          {currentView === 'diary' && renderDiaryView()}
          {currentView === 'ai-chat' && renderAIChatView()}
          {currentView === 'mod-chat' && renderModChatView()}
          {currentView === 'friends' && renderFriendsView()}
          {currentView === 'settings' && renderSettingsView()}
          {currentView === 'admin' && isAdmin && renderAdminView()}
        </div>

        {false && chatOpen && privateChat.active && (
          <div className={styles.chatCard}>
            <div className={styles.chatHeader}>
              <div className={styles.chatUser}>
                <div className={styles.chatAvatar}>👤</div>
                <div className={styles.chatInfo}>
                  <div className={styles.chatName}>Prywatna rozmowa</div>
                  <div className={styles.chatSubtitle}>{privateChat.nickname ? `z ${privateChat.nickname}` : 'Wsparcie'}</div>
                </div>
              </div>
              <button
                onClick={() => {
                  setPrivateChat({ active: false });
                  setMessages([]);
                  setChatOpen(false);
                }}
                className={styles.closeButton}
              >
                <span>❌</span> Zakończ
              </button>
            </div>
            <div className={styles.chatBox} id="chat-box">
              {messages.length === 0 ? (
                <div style={{textAlign:'center',padding:'40px 0',color:'#9ca3af'}}>
                  <div style={{fontSize:'48px',marginBottom:'8px'}}>💭</div>
                  <div style={{fontSize:'14px'}}>Napisz pierwszą wiadomość</div>
                </div>
              ) : (
                messages.map((m, i) => (
                  <div key={i} style={{display:'flex',justifyContent: m.sender === 'Ja' ? 'flex-end' : 'flex-start'}}>
                    <div className={`${styles.message} ${m.sender === 'Ja' ? styles.own : styles.other}`}>
                      <div className={styles.messageHeader}>
                        <span>{m.sender}</span>
                        <span>•</span>
                        <span>{new Date(m.timestamp).toLocaleTimeString('pl-PL', { hour: '2-digit', minute: '2-digit' })}</span>
                      </div>
                      <div className={styles.messageText}>{m.message}</div>
                    </div>
                  </div>
                ))
              )}
              <div ref={messagesEndRef} />
            </div>
            <div className={styles.chatInput}>
              <input
                value={newMessage}
                onChange={(e) => setNewMessage(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); } }}
                placeholder="Wpisz wiadomość..."
              />
              <button onClick={sendMessage} className={styles.sendButton}>
                Wyślij
              </button>
            </div>
          </div>
        )}

        {alertBox && <AlertBox alert={alertBox} />}

        {inputModal && inputModal.isOpen && (
          <div style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: 'rgba(0, 0, 0, 0.6)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 10000,
            backdropFilter: 'blur(4px)'
          }}>
            <div style={{
              background: '#fff',
              borderRadius: '24px',
              padding: '32px',
              width: '90%',
              maxWidth: '480px',
              boxShadow: '0 20px 60px rgba(0, 0, 0, 0.3)',
              animation: 'slideIn 0.3s ease-out'
            }}>
              <h3 style={{
                fontSize: '24px',
                fontWeight: '800',
                color: '#1f2937',
                marginBottom: '24px',
                display: 'flex',
                alignItems: 'center',
                gap: '12px'
              }}>
                <span>🔐</span>
                {inputModal.title}
              </h3>
              
              <form onSubmit={(e) => {
                e.preventDefault();
                const formData = new FormData(e.currentTarget);
                const values: Record<string, string> = {};
                inputModal.fields.forEach(field => {
                  values[field.name] = formData.get(field.name) as string || '';
                });
                inputModal.onSubmit(values);
              }}>
                {inputModal.fields.map((field, index) => (
                  <div key={field.name} style={{marginBottom: '20px'}}>
                    <label style={{
                      display: 'block',
                      fontSize: '14px',
                      fontWeight: '600',
                      color: '#374151',
                      marginBottom: '8px'
                    }}>
                      {field.label}
                    </label>
                    <input
                      type={field.type}
                      name={field.name}
                      placeholder={field.placeholder}
                      maxLength={field.maxLength}
                      required
                      autoFocus={index === 0}
                      onChange={field.maxLength && field.type === 'text' ? (e) => {
                        e.target.value = e.target.value.replace(/\D/g, '').slice(0, field.maxLength);
                      } : undefined}
                      style={{
                        width: '100%',
                        padding: '14px 16px',
                        borderRadius: '12px',
                        border: '2px solid #e5e7eb',
                        fontSize: '15px',
                        outline: 'none',
                        transition: 'all 0.3s',
                        fontFamily: field.maxLength ? 'monospace' : 'inherit',
                        letterSpacing: field.maxLength ? '6px' : 'normal',
                        textAlign: field.maxLength ? 'center' : 'left',
                        boxSizing: 'border-box'
                      }}
                      onFocus={(e) => e.target.style.borderColor = '#667eea'}
                      onBlur={(e) => e.target.style.borderColor = '#e5e7eb'}
                    />
                  </div>
                ))}
                
                <div style={{display: 'flex', gap: '12px', marginTop: '28px'}}>
                  <button
                    type="button"
                    onClick={inputModal.onCancel}
                    style={{
                      flex: 1,
                      padding: '14px 28px',
                      borderRadius: '12px',
                      border: '2px solid #e5e7eb',
                      background: '#fff',
                      color: '#6b7280',
                      fontSize: '16px',
                      fontWeight: '600',
                      cursor: 'pointer',
                      transition: 'all 0.3s'
                    }}
                    onMouseEnter={(e) => e.currentTarget.style.background = '#f3f4f6'}
                    onMouseLeave={(e) => e.currentTarget.style.background = '#fff'}
                  >
                    Anuluj
                  </button>
                  <button
                    type="submit"
                    style={{
                      flex: 1,
                      padding: '14px 28px',
                      borderRadius: '12px',
                      border: 'none',
                      background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
                      color: '#fff',
                      fontSize: '16px',
                      fontWeight: '600',
                      cursor: 'pointer',
                      transition: 'all 0.3s',
                      boxShadow: '0 4px 12px rgba(102, 126, 234, 0.4)'
                    }}
                    onMouseEnter={(e) => e.currentTarget.style.transform = 'scale(1.02)'}
                    onMouseLeave={(e) => e.currentTarget.style.transform = 'scale(1)'}
                  >
                    Potwierdź
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}

        {showAllEntriesModal && (
          <div 
            style={{
              position: 'fixed',
              top: 0,
              left: 0,
              right: 0,
              bottom: 0,
              backgroundColor: 'rgba(0,0,0,0.5)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              zIndex: 9999,
              padding: '20px'
            }}
            onClick={() => setShowAllEntriesModal(false)}
          >
            <div 
              style={{
                backgroundColor: '#fff',
                borderRadius: '16px',
                padding: '32px',
                maxWidth: '800px',
                width: '100%',
                maxHeight: '80vh',
                overflow: 'auto',
                boxShadow: '0 20px 60px rgba(0,0,0,0.3)'
              }}
              onClick={(e) => e.stopPropagation()}
            >
              <div style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                marginBottom: '24px',
                borderBottom: '2px solid #f3f4f6',
                paddingBottom: '16px'
              }}>
                <h2 style={{
                  fontSize: '24px',
                  fontWeight: '700',
                  color: '#111827',
                  margin: 0
                }}>
                  Wszystkie wpisy
                </h2>
                <button
                  onClick={() => setShowAllEntriesModal(false)}
                  style={{
                    background: 'none',
                    border: 'none',
                    fontSize: '28px',
                    cursor: 'pointer',
                    color: '#6b7280',
                    padding: '0',
                    width: '32px',
                    height: '32px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    borderRadius: '8px',
                    transition: 'all 0.2s'
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.backgroundColor = '#f3f4f6';
                    e.currentTarget.style.color = '#111827';
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.backgroundColor = 'transparent';
                    e.currentTarget.style.color = '#6b7280';
                  }}
                >
                  ✕
                </button>
              </div>
              
              {entries.length === 0 ? (
                <div style={{
                  textAlign: 'center',
                  padding: '48px 24px',
                  color: '#6b7280',
                  fontSize: '16px'
                }}>
                  Brak wpisów. Zacznij zapisywać swoje nastroje!
                </div>
              ) : (
                <div style={{
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '16px'
                }}>
                  {entries.map((e) => (
                    <div 
                      key={e.id} 
                      style={{
                        padding: '20px',
                        backgroundColor: '#f9fafb',
                        borderRadius: '12px',
                        border: '1px solid #e5e7eb',
                        transition: 'all 0.2s'
                      }}
                      onMouseEnter={(e) => {
                        e.currentTarget.style.borderColor = '#667eea';
                        e.currentTarget.style.backgroundColor = '#f3f4f6';
                      }}
                      onMouseLeave={(e) => {
                        e.currentTarget.style.borderColor = '#e5e7eb';
                        e.currentTarget.style.backgroundColor = '#f9fafb';
                      }}
                    >
                      <div style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        marginBottom: '12px'
                      }}>
                        <div style={{
                          display: 'inline-block',
                          padding: '6px 14px',
                          borderRadius: '20px',
                          background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
                          color: '#fff',
                          fontWeight: '600',
                          fontSize: '14px'
                        }}>
                          Nastrój: {e.mood}/5
                        </div>
                        <span style={{
                          color: '#6b7280',
                          fontSize: '14px'
                        }}>
                          🕐 {new Date(e.createdAt).toLocaleString('pl-PL', { 
                            day: 'numeric', 
                            month: 'short',
                            year: 'numeric',
                            hour: '2-digit', 
                            minute: '2-digit' 
                          })}
                        </span>
                      </div>
                      <p style={{
                        margin: '0 0 12px 0',
                        color: '#374151',
                        fontSize: '15px',
                        lineHeight: '1.6'
                      }}>
                        {e.note || 'Brak notatki'}
                      </p>
                      <button
                        onClick={() => handleDeleteMood(e.id)}
                        style={{
                          padding: '8px 16px',
                          borderRadius: '8px',
                          border: '1px solid #dc2626',
                          backgroundColor: 'transparent',
                          color: '#dc2626',
                          fontSize: '14px',
                          fontWeight: '600',
                          cursor: 'pointer',
                          transition: 'all 0.2s'
                        }}
                        onMouseEnter={(e) => {
                          e.currentTarget.style.backgroundColor = '#dc2626';
                          e.currentTarget.style.color = '#fff';
                        }}
                        onMouseLeave={(e) => {
                          e.currentTarget.style.backgroundColor = 'transparent';
                          e.currentTarget.style.color = '#dc2626';
                        }}
                      >
                        Usuń
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {notifications.length > 0 && (
          <div className={notificationStyles.notificationsContainer}>
            {notifications.map(notification => {
              console.log('Rendering notification:', notification);
              return <Notification key={notification.id} {...notification} />;
            })}
          </div>
        )}
      </div>
    </div>
  );
}
