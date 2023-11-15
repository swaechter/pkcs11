package ch.swaechter.pkcs11.templates;

import java.lang.foreign.Arena;
import java.lang.foreign.GroupLayout;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.invoke.VarHandle;

import static java.lang.foreign.ValueLayout.*;

/**
 * Template that represents a Windows system with packed struct layouts, mostly Windows x64. Long takes 4 bytes.
 *
 * @author Simon Wächter
 */
public class PackedWindowsTemplate extends Template {

    /**
     * {@inheritDoc}
     */
    @Override
    public MemorySegment allocateLong(Arena arena) {
        return arena.allocate(JAVA_INT);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public MemorySegment allocateLong(Arena arena, long value) {
        return arena.allocate(JAVA_INT, (int) value);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public MemorySegment allocateLongArray(Arena arena, int size) {
        return arena.allocateArray(JAVA_INT, size);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public long getLong(MemorySegment memorySegment) {
        return memorySegment.get(JAVA_INT, 0);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public long getLongFromArray(MemorySegment memorySegment, long index) {
        return memorySegment.get(JAVA_INT, JAVA_INT.byteSize() * index);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public long getLong(MemorySegment memorySegment, GroupLayout groupLayout, String name) {
        VarHandle varHandle = groupLayout.varHandle(MemoryLayout.PathElement.groupElement(name));
        return (int) varHandle.get(memorySegment);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected GroupLayout buildCkVersionLayout() {
        return MemoryLayout.structLayout(
            JAVA_BYTE.withName("major"),
            JAVA_BYTE.withName("minor")
        );
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected GroupLayout buildCkInfoLayout() {
        return MemoryLayout.structLayout(
            getCkVersionLayout().withName("cryptokiVersion"),
            MemoryLayout.sequenceLayout(32, JAVA_BYTE).withName("manufacturerId"),
            JAVA_INT_UNALIGNED.withName("flags"),
            MemoryLayout.sequenceLayout(32, JAVA_BYTE).withName("libraryDescription"),
            getCkVersionLayout().withName("libraryVersion")
        ).withName("CK_INFO");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected GroupLayout buildCkSlotInfoLayout() {
        return MemoryLayout.structLayout(
            MemoryLayout.sequenceLayout(64, JAVA_BYTE).withName("slotDescription"),
            MemoryLayout.sequenceLayout(32, JAVA_BYTE).withName("manufacturerId"),
            JAVA_INT_UNALIGNED.withName("flags"),
            getCkVersionLayout().withName("hardwareVersion"),
            getCkVersionLayout().withName("firmwareVersion")
        ).withName("CK_SLOT_INFO");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected GroupLayout buildCkTokenInfoLayout() {
        return MemoryLayout.structLayout(
            MemoryLayout.sequenceLayout(32, JAVA_BYTE).withName("label"),
            MemoryLayout.sequenceLayout(32, JAVA_BYTE).withName("manufacturerId"),
            MemoryLayout.sequenceLayout(16, JAVA_BYTE).withName("model"),
            MemoryLayout.sequenceLayout(16, JAVA_BYTE).withName("serialNumber"),
            JAVA_INT_UNALIGNED.withName("flags"),
            JAVA_INT_UNALIGNED.withName("maxSessionCount"),
            JAVA_INT_UNALIGNED.withName("sessionCount"),
            JAVA_INT_UNALIGNED.withName("maxRwSessionCount"),
            JAVA_INT_UNALIGNED.withName("rwSessionCount"),
            JAVA_INT_UNALIGNED.withName("maxPinLen"),
            JAVA_INT_UNALIGNED.withName("minPinLen"),
            JAVA_INT_UNALIGNED.withName("totalPublicMemory"),
            JAVA_INT_UNALIGNED.withName("freePublicMemory"),
            JAVA_INT_UNALIGNED.withName("totalPrivateMemory"),
            JAVA_INT_UNALIGNED.withName("freePrivateMemory"),
            getCkVersionLayout().withName("hardwareVersion"),
            getCkVersionLayout().withName("firmwareVersion"),
            MemoryLayout.sequenceLayout(16, JAVA_BYTE).withName("utcTime")
        ).withName("CK_TOKEN_INFO");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected GroupLayout buildCkSessionInfoLayout() {
        return MemoryLayout.structLayout(
            JAVA_INT_UNALIGNED.withName("slotId"),
            JAVA_INT_UNALIGNED.withName("state"),
            JAVA_INT_UNALIGNED.withName("flags"),
            JAVA_INT_UNALIGNED.withName("deviceError")
        ).withName("CK_SESSION_INFO");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected GroupLayout buildCkAttributeLayout() {
        return MemoryLayout.structLayout(
            JAVA_INT_UNALIGNED.withName("type"),
            ADDRESS_UNALIGNED.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)).withName("pValue"),
            JAVA_INT_UNALIGNED.withName("valueLen")
        ).withName("CK_ATTRIBUTE");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected GroupLayout buildCkMechanismLayout() {
        return MemoryLayout.structLayout(
            JAVA_INT_UNALIGNED.withName("mechanism"),
            ADDRESS_UNALIGNED.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)).withName("pParameter"),
            JAVA_INT_UNALIGNED.withName("parameterLen")
        ).withName("CK_MECHANISM");
    }
}
