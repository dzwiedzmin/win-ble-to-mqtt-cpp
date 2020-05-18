// BLEScanner.cpp : Scans for a Xiaomi temperature and humidity sensos, connects to them, authenticates and redirects readings to mqtt
//
// Copyright (C) 2020, Tomasz Niedüwiecki. License: GPT.
//
// Heavily based on:
// https://github.com/urish/win-ble-cpp
// https://github.com/drndos/mi-kettle-poc
// 



#include "stdafx.h"
#include "mosquittopp.h"
#include <iostream>
#include <regex>
#include <assert.h>
#include <Windows.Foundation.h>
#include <Windows.Devices.Bluetooth.h>
#include <Windows.Devices.Bluetooth.Advertisement.h>
#include <wrl/wrappers/corewrappers.h>
#include <wrl/event.h>
#include <collection.h>
#include <ppltasks.h>
#include <string>
#include <vector>
#include <unordered_set>
#include <mutex>
#include <sstream> 
#include <iomanip>
#include <cstdint>
#include <numeric>
#include <experimental/resumable>
#include <pplawait.h>


using namespace Platform;
using namespace Windows::Devices;
using namespace Windows::Devices::Bluetooth::GenericAttributeProfile;

std::mutex mqtt_mutex;
std::mutex device_mutex;
mosqpp::mosquittopp *mqtt = nullptr;

std::unordered_set<unsigned long long> devices;

class mqtt_temphumid : public mosqpp::mosquittopp
{
public:
	mqtt_temphumid(const char *host, int port=1883) : mosquittopp("mqtt") 
	{ 
		mosqpp::lib_init();
		connect(host, port, 60); 
	}
	~mqtt_temphumid() {
		mqtt->loop_stop();
		mosqpp::lib_cleanup();
	};

};


void SendMQTT(std::string topic, std::string value)
{
	//c:\Program Files\mosquitto\mosquitto_pub.exe -t "sensors/BLE/582d343a840a/temp" -h localhost -m "12.3"
	//std::string cmd = "cmd /S /C \"\"c:\\Program Files\\mosquitto\\mosquitto_pub.exe\" -t \"" + topic + "\" -h localhost -m \"" + value + "\"\" > nul";
	//system(cmd.c_str());

	int res = 0;
	const char *buf = value.c_str();

	mqtt_mutex.lock();
	res = mqtt->publish(NULL, topic.c_str(), (int)strlen(buf), buf);
	if ( res != 0)
	{
		std::cout << std::string("mqtt_send error=" + std::to_string(res) + "\n");
		mqtt->reconnect();

	}
	mqtt_mutex.unlock();

}

std::string formatBluetoothAddress(unsigned long long BluetoothAddress, std::string sep= ":") {
	std::ostringstream ret;
	ret << std::hex << std::setfill('0')
		<< std::setw(2) << ((BluetoothAddress >> (5 * 8)) & 0xff) << sep << std::setw(2) << ((BluetoothAddress >> (4 * 8)) & 0xff) << sep << std::setw(2) << ((BluetoothAddress >> (3 * 8)) & 0xff) << sep
		<< std::setw(2) << ((BluetoothAddress >> (2 * 8)) & 0xff) << sep << std::setw(2) << ((BluetoothAddress >> (1 * 8)) & 0xff) << sep << std::setw(2) << ((BluetoothAddress >> (0 * 8)) & 0xff);
	return ret.str();
}

GUID StringToGUID(Platform::String^ str)
{
	GUID rawguid;
	HRESULT hr = IIDFromString(str->Data(), &rawguid);
	assert(SUCCEEDED(hr));
	return rawguid;
}


std::vector<unsigned char> getData(::Windows::Storage::Streams::IBuffer^ buf)
{

	auto reader = ::Windows::Storage::Streams::DataReader::FromBuffer(buf);

	std::vector<unsigned char> data(reader->UnconsumedBufferLength);

	if (!data.empty())
		reader->ReadBytes(::Platform::ArrayReference<unsigned char>(&data[0], (unsigned int)data.size()));

	return data;
}



//https://docs.microsoft.com/en-us/uwp/api/windows.devices.bluetooth.genericattributeprofile.gattdeviceservice.getcharacteristicsasync?view=winrt-18362
//https://docs.microsoft.com/en-us/uwp/api/windows.devices.bluetooth.genericattributeprofile.gattcommunicationstatus?view=winrt-18362
//https://docs.microsoft.com/en-us/uwp/api/windows.devices.bluetooth.genericattributeprofile.gattcharacteristicproperties?view=winrt-18362

#define GetGattServiceOnly(desc, serviceUUID)                                                                                                                    \
	auto servicesResult = co_await leDevice->GetGattServicesForUuidAsync(serviceUUID);                                                                           \
	std::cout << "SERVICES [" << desc << "]: " << servicesResult->Services->Size /*<< std::endl*/;                                                               \
	if (!servicesResult->Services->Size) {Sleep(10000);continue;};                                                                                               \
	auto service = servicesResult->Services->GetAt(0);                                                                                                           \
	auto access = co_await service->RequestAccessAsync();                                                                                                        \
	std::wcout << "   ACCESS: " << (int)access << std::endl;                                                                                                     \

#define GetGattCharacteristic(desc, service, characteristicUUID, characteristic)                                                                                 \
    {                                                                                                                                                            \
	auto characteristicsResult = co_await service->GetCharacteristicsForUuidAsync(characteristicUUID, Bluetooth::BluetoothCacheMode::Uncached);                  \
	std::cout << "CHARS [" << desc << "]: " << characteristicsResult->Characteristics->Size << " STATUS:  " << (int)characteristicsResult->Status;               \
	if (!characteristicsResult->Characteristics->Size) {Sleep(10000);continue;};                                                                                 \
	characteristic = characteristicsResult->Characteristics->GetAt(0);                                                                                           \
    int props = (int)characteristic->CharacteristicProperties;                                                                                                   \
	std::wcout << "   UUID " << characteristic->Uuid.ToString()->Data();                                                                                         \
	std::wcout << "   HND " << characteristic->AttributeHandle;                                                                                                  \
	std::wcout << "   PROPS " << props << std::endl;                                                                                                             \
	}                                                                                                                                                            \


#define GetGattServiceAndCharacteristic(desc, serviceUUID, characteristicUUID, characteristic)                                                                   \
    {                                                                                                                                                            \
	GetGattServiceOnly(desc, serviceUUID);																												         \
	GetGattCharacteristic(desc, service, characteristicUUID, characteristic);																					 \
    }                                                                                                                                                            \


concurrency::task<void> auth(Bluetooth::BluetoothLEDevice ^leDevice) {

	std::string mac = formatBluetoothAddress(leDevice->BluetoothAddress, "");
	
	//https://github.com/aprosvetova/xiaomi-kettle/blob/master/cipher.go
	//https://github.com/drndos/mi-kettle-poc/blob/master/mi-kettle.py
	//https://github.com/sputnikdev/eclipse-smarthome-bluetooth-binding/issues/18
	//Please note, device type of temp sensor is 426.
	//http://reactblog.pl/category/iot/

	uint16_t productID = 426;

	auto ba = leDevice->BluetoothAddress;
	std::vector<uint8_t> revmac{ uint8_t((ba >> (0 * 8)) & 0xff), uint8_t((ba >> (1 * 8)) & 0xff) , uint8_t((ba >> (2 * 8)) & 0xff) , uint8_t((ba >> (3 * 8)) & 0xff) , uint8_t((ba >> (4 * 8)) & 0xff) , uint8_t((ba >> (5 * 8)) & 0xff) };
	std::vector<uint8_t> TOKEN{ 0x01, 0x5C, 0xCB, 0xA8, 0x80, 0x0A, 0xBD, 0xC1, 0x2E, 0xB8, 0xED, 0x82 }; //any random tab should work
	std::vector<uint8_t> KEY1{ 0x90, 0xCA, 0x85, 0xDE };

	auto mixA = [](std::vector<uint8_t> &mac, uint16_t productID) -> std::vector<uint8_t>
	{
		return { mac[0], mac[2], mac[5], uint8_t(productID & 0xff), uint8_t(productID & 0xff), mac[4], mac[5], mac[1] };
	};


	auto mixB = [](std::vector<uint8_t> &mac, uint16_t productID) -> std::vector<uint8_t>
	{
		return { mac[0], mac[2], mac[5], uint8_t((productID >> 8) & 0xff), mac[4], mac[0], mac[5], uint8_t(productID & 0xff) };
	};

	auto cipherInit = [](const std::vector<uint8_t> &key) -> std::vector<uint8_t>
	{
		std::vector<uint8_t> perm(256);
		std::iota(perm.begin(), perm.end(), 0);

		uint16_t j = 0;
		for (int i = 0; i < perm.size(); i++)
		{
			j += perm[i] + key[i % key.size()];
			j = j & 0xff;			
			std::swap(perm[i], perm[j]);
		}

		return perm;
	};

	
	auto cipherCrypt = [](const std::vector<uint8_t> &input, std::vector<uint8_t> &perm) -> std::vector<uint8_t>
	{
		uint16_t idx    = 0;
		uint16_t index1 = 0;
		uint16_t index2 = 0;
		std::vector<uint8_t> output;

		for (int i = 0; i < input.size(); i++)
		{
			index1 = (index1 + 1) & 0xff;
			index2 = (index2 + perm[index1]) & 0xff;
			std::swap(perm[index1], perm[index2]);
			idx = perm[index1] + perm[index2];
			idx = idx & 0xff;
			output.push_back((input[i] ^ perm[idx]) & 0xff);
		}

		return output;
	};

	auto cipher = [cipherInit, cipherCrypt](const std::vector<uint8_t> &key, const std::vector<uint8_t> &input) ->std::vector<uint8_t>
	{
		auto perm = cipherInit(key);
		return cipherCrypt(input, perm);
	};
	
	auto data = cipher(mixA(revmac, productID), TOKEN);




	while (1)
	{
		try
		{
			GattCharacteristic ^aiCharacteristic;
			GattCharacteristic ^aCharacteristic;
			GattCharacteristic ^rCharacteristic;
			GetGattServiceOnly("AUTH " + mac, Bluetooth::BluetoothUuidHelper::FromShortId(0xFE95));
			GetGattCharacteristic("AUTH INIT " + mac, service, Bluetooth::BluetoothUuidHelper::FromShortId(0x0010), aiCharacteristic);
			GetGattCharacteristic("AUTH " + mac, service, Bluetooth::BluetoothUuidHelper::FromShortId(0x0001), aCharacteristic);


			{
				auto writer = ref new Windows::Storage::Streams::DataWriter();
				writer->WriteBytes(ref new Array<byte>(KEY1.data(), (unsigned int)KEY1.size()));
				//https://docs.microsoft.com/en-us/uwp/api/windows.devices.bluetooth.genericattributeprofile.gattcommunicationstatus?view=winrt-18362
				auto aiStatus = co_await aiCharacteristic->WriteValueAsync(writer->DetachBuffer(), Bluetooth::GenericAttributeProfile::GattWriteOption::WriteWithResponse);
				std::cout << "WRITE: " << (int)aiStatus << std::endl;
			}




			bool ok = false;
			aCharacteristic->ValueChanged += ref new Windows::Foundation::TypedEventHandler<GattCharacteristic ^, GattValueChangedEventArgs ^>(
				[mac, &ok](GattCharacteristic ^sender, GattValueChangedEventArgs^ args) {

				auto data = getData(args->CharacteristicValue);
				std::cout << "AUTH NOTIFY [" + mac + "]: ";
				for (auto r : data)
					std::cout << "0x" << std::hex << std::setfill('0') << std::setw(2) << (int)r << ", ";
				std::cout << std::endl;

				ok = true;
			});;


			auto notifyResult = co_await aCharacteristic->WriteClientCharacteristicConfigurationDescriptorAsync(GattClientCharacteristicConfigurationDescriptorValue::Notify);

			switch (notifyResult) {
			case GattCommunicationStatus::AccessDenied:
				std::cout << "access denied" << std::endl;
				break;
			case GattCommunicationStatus::ProtocolError:
				std::cout << "protocol error" << std::endl;
				break;
			case GattCommunicationStatus::Unreachable:
				std::cout << "unreachable" << std::endl;
				break;
			case GattCommunicationStatus::Success:
				std::cout << "success" << std::endl;
				break;
			}




			{
				auto writer = ref new Windows::Storage::Streams::DataWriter();
				writer->WriteBytes(ref new Array<byte>(data.data(), (unsigned int)data.size()));
				auto aStatus = co_await aCharacteristic->WriteValueAsync(writer->DetachBuffer(), Bluetooth::GenericAttributeProfile::GattWriteOption::WriteWithResponse);
				std::cout << "WRITE: " << (int)aStatus << std::endl;
			}

			Sleep(50);
			std::cout << "OK: " << ok << std::endl;
			notifyResult = co_await aCharacteristic->WriteClientCharacteristicConfigurationDescriptorAsync(GattClientCharacteristicConfigurationDescriptorValue::None);

			//aCharacteristic->ValueChanged -;

			{
				auto writer = ref new Windows::Storage::Streams::DataWriter();
				auto KEY2 = cipher(TOKEN, { 0x92, 0xAB, 0x54, 0xFA });
				writer->WriteBytes(ref new Array<byte>(KEY2.data(), (unsigned int)KEY2.size()));
				auto aStatus = co_await aCharacteristic->WriteValueAsync(writer->DetachBuffer(), Bluetooth::GenericAttributeProfile::GattWriteOption::WriteWithResponse);
				std::cout << "WRITE: " << (int)aStatus << std::endl;
			}

			//Sleep(300);

			//auto c = service->GetCharacteristics(Bluetooth::BluetoothUuidHelper::FromShortId(0x0004));
			//co_await c->GetAt(0)->ReadValueAsync();

			GetGattCharacteristic("AUTH END " + mac, service, Bluetooth::BluetoothUuidHelper::FromShortId(0x0004), rCharacteristic);
			auto cval = co_await rCharacteristic->ReadValueAsync(); //just read it :)

			return;
		}
		catch (...)
		{
			// catch any other errors (that we have no information about)
			std::cout << "AUTH ERROR[" + mac + "]" << std::endl;			
		}
		Sleep(5000); // check again in a while
	}



}

concurrency::task<void> batteryCheck(Bluetooth::BluetoothLEDevice ^leDevice) {

	std::string mac = formatBluetoothAddress(leDevice->BluetoothAddress, "");

	try 
	{
		while (1)
		{
			GattCharacteristic ^batCharacteristic;
			GetGattServiceAndCharacteristic("BATTERY " + mac, Bluetooth::BluetoothUuidHelper::FromShortId(0x180f), Bluetooth::BluetoothUuidHelper::FromShortId(0x2a19), batCharacteristic);

			auto cval = co_await batCharacteristic->ReadValueAsync(Windows::Devices::Bluetooth::BluetoothCacheMode::Uncached);
			if (cval->Value)
			{

				auto data = getData(cval->Value);
				std::cout << "BATTERY[" + mac + "]" << (int)data.front() << std::endl;

				SendMQTT("sensors/BLE/" + mac + "/batt", std::to_string(data.front()));
				return;
			}

			Sleep(5000); // check again in a while
		}

	}
	catch (...)
	{
		std::cout << "BATTERY CHECK ERROR[" + mac + "]" << std::endl;
	}

}


concurrency::task<void> connectToXiaomiTempSensor(unsigned long long bluetoothAddress) {
	
	device_mutex.lock();
	devices.insert(bluetoothAddress);
	device_mutex.unlock();

	int BatteryCheckInterval = 3600; // seconds;
	
	auto serviceUUID = StringToGUID("{226c0000-6476-4566-7562-66734470666d}");
	auto characteristicUUID = StringToGUID("{226caa55-6476-4566-7562-66734470666d}");

	while (1)
	{
		try
		{
			auto leDevice = co_await Bluetooth::BluetoothLEDevice::FromBluetoothAddressAsync(bluetoothAddress);
			std::string mac = formatBluetoothAddress(bluetoothAddress, "");

			co_await auth(leDevice);

			GattCharacteristic ^characteristic;
			GetGattServiceAndCharacteristic("DATA " + mac, serviceUUID, characteristicUUID, characteristic);


			//Write the CCCD in order for server to send notifications.     
			auto notifyResult = co_await characteristic->WriteClientCharacteristicConfigurationDescriptorAsync(GattClientCharacteristicConfigurationDescriptorValue::Notify);

			switch (notifyResult) {
			case GattCommunicationStatus::AccessDenied:
				std::cout << "access denied" << std::endl;
				break;
			case GattCommunicationStatus::ProtocolError:
				std::cout << "protocol error" << std::endl;
				break;
			case GattCommunicationStatus::Unreachable:
				std::cout << "unreachable" << std::endl;
				break;
			case GattCommunicationStatus::Success:
				//std::cout << "success" << std::endl;
				break;
			}

			if (notifyResult != GattCommunicationStatus::Success)
				continue;


			characteristic->ValueChanged += ref new Windows::Foundation::TypedEventHandler<GattCharacteristic ^, GattValueChangedEventArgs ^>(
				[mac](GattCharacteristic ^sender, GattValueChangedEventArgs^ args) {

				auto data = getData(args->CharacteristicValue);
				std::string s(data.begin(), data.end());

				std::cout << "NOTIFY[" + mac + "] [" << s << "]" << std::endl;

				std::smatch m;
				std::regex reg("T=(.*) H=(.*)");
				if (std::regex_match(s, m, reg))
				{
					SendMQTT("sensors/BLE/" + mac + "/temp", m[1].str());
					SendMQTT("sensors/BLE/" + mac + "/humid", m[2].str());
					//std::cout << m.size() << std::endl;
				}
			});

			batteryCheck(leDevice);
			Sleep(BatteryCheckInterval * 1000);
		}
		catch (Exception^ ex)
		{
			std::wcout << "Platform:Exception: " << ex->Message->ToString()->Data() << std::endl;
			continue;
		}
		catch (const std::runtime_error& re)
		{
			// speciffic handling for runtime_error
			std::cout << "Runtime error: " << re.what() << std::endl;
			continue;
		}
		catch (const std::exception& ex)
		{
			// speciffic handling for all exceptions extending std::exception, except
			// std::runtime_error which is handled explicitly
			std::cout << "Error occurred: " << ex.what() << std::endl;
			continue;
		}
		catch (...)
		{
			// catch any other errors (that we have no information about)
			std::cout << "Unknown failure occurred. Possible memory corruption" << std::endl;
			continue;
		}

	}


}



int main(Array<String^>^ args) {
	Microsoft::WRL::Wrappers::RoInitializeWrapper initialize(RO_INIT_MULTITHREADED);
	CoInitializeSecurity(nullptr,  -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IDENTIFY, NULL, EOAC_NONE, nullptr);
	
	mqtt = new mqtt_temphumid("192.168.68.125");

	//add known devises [the INT= one] here for faster startup
	connectToXiaomiTempSensor(96951173022730);
	connectToXiaomiTempSensor(96951173020050);

	Bluetooth::Advertisement::BluetoothLEAdvertisementWatcher^ bleWatch = ref new Bluetooth::Advertisement::BluetoothLEAdvertisementWatcher();
	bleWatch->Received += ref new Windows::Foundation::TypedEventHandler<Bluetooth::Advertisement::BluetoothLEAdvertisementWatcher ^, Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementReceivedEventArgs ^>(
		[](Bluetooth::Advertisement::BluetoothLEAdvertisementWatcher ^watcher, Bluetooth::Advertisement::BluetoothLEAdvertisementReceivedEventArgs^ eventArgs) {

		auto adv = eventArgs->Advertisement; //https://docs.microsoft.com/en-us/uwp/api/windows.devices.bluetooth.advertisement.bluetoothleadvertisement?view=winrt-18362

		std::string mac = formatBluetoothAddress(eventArgs->BluetoothAddress, ":");
		auto name = adv->LocalName;
		if (0 && name->Length())
		{
			std::wcout << "\t\t[Advertisement] NAME=" << name->Data();
			std::cout << "   MAC=" << mac << std::endl;
		}
		

		unsigned int index = -1;
		auto serviceUUID = Bluetooth::BluetoothUuidHelper::FromShortId(0x180f);
		if (adv->ServiceUuids->IndexOf(serviceUUID, &index))
		{
			device_mutex.lock();
			bool skip = (devices.find(eventArgs->BluetoothAddress) != devices.end());
			device_mutex.unlock();
			if (skip) 
				return;



			std::string mac = formatBluetoothAddress(eventArgs->BluetoothAddress, ":");
			std::cout << "DEVICE[MAC=" << mac << "   INT=" << std::to_string(eventArgs->BluetoothAddress) << "]  ";
			std::wcout << adv->LocalName->Data() << std::endl;

			//printf("unsigned long long int: %llu\n", eventArgs->BluetoothAddress);


			
			connectToXiaomiTempSensor(eventArgs->BluetoothAddress);

		}
	});
	bleWatch->ScanningMode = Bluetooth::Advertisement::BluetoothLEScanningMode::Active;
	bleWatch->Start();
	getchar();

	
	delete mqtt;

	return 0;
}

